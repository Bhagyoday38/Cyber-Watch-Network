import asyncio
import math
import os
import threading
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, UploadFile, File, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff
# Fixes Pylance dynamic import errors
from scapy.layers.inet import IP, TCP, UDP

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
MAX_QUEUED_PACKETS = 256
MAX_UPLOAD_SIZE = 50 * 1024 * 1024
ALLOWED_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")
packet_subscribers: set[asyncio.Queue] = set()
loop: asyncio.AbstractEventLoop | None = None

# ---------------------------------------------------------------------------
# Suspicious port classification
# ---------------------------------------------------------------------------
SUSPICIOUS_PORTS = {
    23: "Telnet",
    135: "MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3389: "RDP",
    4444: "Metasploit",
    6667: "IRC (C2)",
    8080: "Alt-HTTP Proxy",
    31337: "Back Orifice",
}

SCAN_WINDOW_SECONDS = 10
SCAN_PORT_THRESHOLD = 5
MAX_TRACKED_FLOWS = 4096
MAX_ATTEMPTS_PER_FLOW = 64
scan_attempts: OrderedDict[tuple[str, str], deque] = OrderedDict()

ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".ppt", ".pptx"}


def classify_packet(packet) -> tuple[str, int, str]:
    """
    Returns (threat_level, rule_score, threat_type).
    """
    if not packet.haslayer(TCP) and not packet.haslayer(UDP):
        return "Normal", 5, "None"

    dst_port = None
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        if packet.haslayer(IP) and flags == 0x02 and _is_port_scan_attempt(packet):
            return "Suspicious", 55, "Port Scan"

        if dst_port in SUSPICIOUS_PORTS:
            label = SUSPICIOUS_PORTS[dst_port]
            return "Suspicious", 55, label

    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        src_port = packet[UDP].sport
        if src_port == 53 and len(packet) > 512:
            return "Suspicious", 60, "Large DNS Response"

    return "Normal", 5, "None"


def _is_port_scan_attempt(packet) -> bool:
    # shortcut: detects vertical TCP SYN scans only; cross-destination tracking is needed for horizontal scans.
    flow = (packet[IP].src, packet[IP].dst)
    attempts = scan_attempts.get(flow)
    if attempts is None:
        attempts = deque()
        scan_attempts[flow] = attempts
        if len(scan_attempts) > MAX_TRACKED_FLOWS:
            scan_attempts.popitem(last=False)
    else:
        scan_attempts.move_to_end(flow)

    packet_time = float(packet.time)
    while attempts and packet_time - attempts[0][0] > SCAN_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= MAX_ATTEMPTS_PER_FLOW:
        attempts.popleft()

    attempts.append((packet_time, packet[TCP].dport))
    return len({port for _, port in attempts}) >= SCAN_PORT_THRESHOLD


def publish_packet(packet_data: dict):
    for subscriber in tuple(packet_subscribers):
        if subscriber.full():
            # Keep each browser current without growing memory for slow clients.
            subscriber.get_nowait()
        subscriber.put_nowait(packet_data)


def is_allowed_origin(origin: str | None) -> bool:
    return origin is None or origin in ALLOWED_ORIGINS


def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    threat_level, rule_score, threat_type = classify_packet(packet)

    protocol = (
        "TCP" if packet.haslayer(TCP)
        else "UDP" if packet.haslayer(UDP)
        else "IP"
    )

    dst_port = None
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    packet_data = {
        "time": float(packet.time),
        "source": packet[IP].src,
        "destination": packet[IP].dst,
        "protocol": protocol,
        "length": len(packet),
        "dst_port": dst_port,
        "threat": threat_level,
        "threat_type": threat_type,
        "rule_score": rule_score,
    }

    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(publish_packet, packet_data)


def start_sniffing():
    sniff(prn=packet_callback, store=0)


# ---------------------------------------------------------------------------
# File threat analysis
# ---------------------------------------------------------------------------
MALICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".pif", ".com", ".hta", ".msi",
}

SUSPICIOUS_KEYWORDS = {
    "virus", "malware", "trojan", "ransomware", "keylogger",
    "payload", "exploit", "dropper", "backdoor", "rootkit",
}


def analyze_file(filename: str, content: bytes) -> dict:
    name_lower = filename.lower()
    ext = os.path.splitext(name_lower)[1]
    risk = 0
    flags = []

    # Extension-based risk
    if ext in MALICIOUS_EXTENSIONS:
        risk += 55
        flags.append(f"Executable extension ({ext})")

    # Name-based heuristics
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in name_lower:
            risk += 30
            flags.append(f'Suspicious keyword "{kw}" in filename')
            break

    # Entropy check (high entropy → possible packed/encrypted payload)
    if content:
        entropy = _shannon_entropy(content)
        if entropy > 7.2:
            risk += 20
            flags.append(f"High entropy ({entropy:.2f} bits/byte)")
        elif entropy > 6.5:
            risk += 8

    # Executables disguised as documents must never receive a safe verdict.
    if content[:2] == b"MZ":
        risk = max(risk, 90)
        if "Executable extension" not in str(flags):
            flags.append("PE executable magic bytes (MZ header)")

    # Clamp to [0, 100]
    risk = min(risk, 100)
    status = "Malicious" if risk >= 60 else "Suspicious" if risk >= 30 else "No known indicators"

    return {
        "filename": filename,
        "status": status,
        "risk_score": risk,
        "flags": flags,
        "file_size": len(content),
    }


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def validate_upload_content(content: bytes):
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds the 50 MB limit.")
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()
    print("🚀 Packet sniffing started — ensure Npcap is installed and run as Admin.")
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------------------
# WebSocket — live packets
# ---------------------------------------------------------------------------
@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    if not is_allowed_origin(websocket.headers.get("origin")):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    subscriber = asyncio.Queue(maxsize=MAX_QUEUED_PACKETS)
    packet_subscribers.add(subscriber)
    try:
        while True:
            packet = await subscriber.get()
            await websocket.send_json(packet)
    except WebSocketDisconnect:
        pass
    finally:
        packet_subscribers.discard(subscriber)


# ---------------------------------------------------------------------------
# File upload — threat analyzer
# ---------------------------------------------------------------------------
@app.post("/upload-file")
async def upload_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400, detail="Invalid filename provided.")

    filename = file.filename.lower()
    ext = os.path.splitext(filename)[1]

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail="Only PDF, DOC, DOCX, PPT, and PPTX files are supported.",
        )

    content = await file.read(MAX_UPLOAD_SIZE + 1)
    validate_upload_content(content)
    result = analyze_file(file.filename, content)

    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
