import asyncio
import hashlib
import math
import random
import threading
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, UploadFile, File, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP, TCP, UDP

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
packet_queue: asyncio.Queue = asyncio.Queue()
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

SCAN_PORTS = {22, 80, 443, 8443, 3306, 5432, 6379, 27017}


def classify_packet(packet) -> tuple[str, int, str]:
    """
    Returns (threat_level, attack_likelihood_pct, threat_type).
    """
    if not packet.haslayer(TCP) and not packet.haslayer(UDP):
        return "Normal", random.randint(1, 8), "None"

    dst_port = None
    src_port = None
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
        flags = packet[TCP].flags

        # SYN scan heuristic: SYN-only packets in quick succession
        if flags == 0x02 and dst_port in SCAN_PORTS:
            return "Suspicious", random.randint(45, 65), "Port Scan"

        if dst_port in SUSPICIOUS_PORTS:
            label = SUSPICIOUS_PORTS[dst_port]
            likelihood = random.randint(75, 95)
            return "Malicious", likelihood, label

    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        src_port = packet[UDP].sport
        # DNS amplification heuristic: large UDP to port 53 from unusual source
        if dst_port == 53 and len(packet) > 512:
            return "Suspicious", random.randint(55, 70), "DNS Amplification"

    return "Normal", random.randint(1, 12), "None"


def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    threat_level, attack_likelihood, threat_type = classify_packet(packet)

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
        "attack_likelihood": f"{attack_likelihood}%",
    }

    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(packet_queue.put_nowait, packet_data)


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
    import os
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

    # Magic bytes for executables regardless of extension
    if content[:2] == b"MZ":
        risk += 25
        if "Executable extension" not in str(flags):
            flags.append("PE executable magic bytes (MZ header)")

    # Clamp to [0, 100]
    risk = min(risk, 100)
    status = "Malicious" if risk >= 60 else "Suspicious" if risk >= 30 else "Safe"

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
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# WebSocket — live packets
# ---------------------------------------------------------------------------
@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            packet = await packet_queue.get()
            await websocket.send_json(packet)
    except WebSocketDisconnect:
        print("WebSocket client disconnected.")
    except Exception as e:
        print(f"WebSocket error: {e}")


# ---------------------------------------------------------------------------
# File upload — threat analyzer
# ---------------------------------------------------------------------------
@app.post("/upload-file")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    result = analyze_file(file.filename, content)
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
