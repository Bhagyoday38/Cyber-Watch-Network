import { useEffect, useState, useRef } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import {
  ShieldAlert, Activity, AlertTriangle, FileSearch, Search, Trash2,
  UploadCloud, CheckCircle, ShieldCheck, AlertCircle, ArrowDownRight, Radio, X,
} from "lucide-react";

// ── Helpers ────────────────────────────────────────────────────────────────

const protocolClass = (p) =>
  ({ TCP: "badge-tcp", UDP: "badge-udp", IP: "badge-ip" }[p] ?? "badge-default");

const scoreClass = (score) => {
  const v = parseInt(score, 10);
  if (isNaN(v)) return "";
  if (v < 10) return "like-low";
  if (v < 50) return "like-med";
  return "like-high";
};

const threatClass = (t) =>
  ({ Malicious: "threat-bad", Suspicious: "threat-warn", Normal: "threat-ok" }[t] ?? "");

const ThreatIcon = ({ threat }) => {
  if (threat === "Malicious") return <AlertTriangle className="icon-xs" />;
  if (threat === "Suspicious") return <AlertCircle className="icon-xs" />;
  return <CheckCircle className="icon-xs" />;
};

const fmtSize = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const fmtTime = (timestamp) =>
  new Date(timestamp * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

// ── Chart colours ──────────────────────────────────────────────────────────
const CHART_COLORS = {
  TCP: "var(--c-cyan)",
  UDP: "var(--c-purple)",
  IP: "var(--c-green)",
};
const EMPTY_COUNTS = { TCP: 0, UDP: 0, IP: 0 };
const EMPTY_THREATS = { Normal: 0, Suspicious: 0, Malicious: 0 };

// ── App ────────────────────────────────────────────────────────────────────

export default function App() {
  const [packets, setPackets] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    protocols: EMPTY_COUNTS,
    threats: EMPTY_THREATS,
  });
  const [alerts, setAlerts] = useState([]);
  const [alertsCleared, setAlertsCleared] = useState(false);
  const [connected, setConnected] = useState(false);
  const [streamError, setStreamError] = useState("");
  const [packetFilter, setPacketFilter] = useState("all");
  const [packetSearch, setPacketSearch] = useState("");
  const wsRef = useRef(null);

  // File analyzer
  const [file, setFile] = useState(null);
  const [fileResult, setFileResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadError, setUploadError] = useState("");

  // ── WebSocket ─────────────────────────────────────────────────────────────
  useEffect(() => {
    let disposed = false;
    let reconnectTimer;
    const connect = () => {
      const socketUrl = new URL("/ws/packets", window.location.href);
      socketUrl.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(socketUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!disposed) setConnected(true);
      };

      ws.onmessage = ({ data }) => {
        if (disposed) return;
        let pkt;
        try {
          pkt = JSON.parse(data);
        } catch {
          setStreamError("The backend sent unreadable packet data.");
          return;
        }
        if (
          !pkt ||
          typeof pkt.time !== "number" ||
          !Number.isFinite(pkt.time) ||
          typeof pkt.source !== "string" ||
          typeof pkt.destination !== "string" ||
          !["TCP", "UDP", "IP"].includes(pkt.protocol) ||
          !["Normal", "Suspicious", "Malicious"].includes(pkt.threat) ||
          !Number.isInteger(pkt.rule_score) ||
          pkt.rule_score < 0 ||
          pkt.rule_score > 100
        ) {
          setStreamError("The backend sent an invalid packet record.");
          return;
        }

        setStreamError("");
        setPackets((prev) => [...prev.slice(-49), pkt]);
        setStats((prev) => ({
          total: prev.total + 1,
          protocols: { ...prev.protocols, [pkt.protocol]: prev.protocols[pkt.protocol] + 1 },
          threats: { ...prev.threats, [pkt.threat]: prev.threats[pkt.threat] + 1 },
        }));
        if (pkt.threat !== "Normal") {
          setAlerts((prev) => [pkt, ...prev.slice(0, 9)]);
          setAlertsCleared(false);
        }
      };

      ws.onerror = () => {
        if (!disposed) setConnected(false);
      };
      ws.onclose = () => {
        if (disposed) return;
        setConnected(false);
        reconnectTimer = setTimeout(connect, 3000);
      };
    };
    connect();
    return () => {
      disposed = true;
      clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, []);

  // ── File upload ───────────────────────────────────────────────────────────
  const handleFile = (f) => {
    setFile(f);
    setFileResult(null);
    setUploadError("");
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  };

  const handleAnalyze = async () => {
    if (!file) return;
    setUploading(true);
    setFileResult(null);
    setUploadError("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch("/api/upload-file", { method: "POST", body: fd });
      const result = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(
          typeof result.detail === "string" ? result.detail : "The file could not be analyzed."
        );
      }
      setFileResult(result);
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : "The file could not be analyzed.");
    } finally {
      setUploading(false);
    }
  };

  const chartData = [
    { name: "TCP", count: stats.protocols.TCP },
    { name: "UDP", count: stats.protocols.UDP },
    { name: "IP", count: stats.protocols.IP },
  ];
  const visiblePackets = [...packets].reverse().filter((packet) => {
    const matchesFilter = packetFilter === "all" || packet.threat !== "Normal";
    const query = packetSearch.trim().toLowerCase();
    const matchesSearch = !query || [
      packet.source,
      packet.destination,
      packet.protocol,
      packet.threat,
      packet.threat_type,
      packet.dst_port,
    ].some((value) => String(value ?? "").toLowerCase().includes(query));
    return matchesFilter && matchesSearch;
  });

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="root">
      <header className="topbar">
        <a className="brand" href="#overview" aria-label="CyberWatch overview">
          <span className="brand-mark"><ShieldAlert size={20} /></span>
          <span className="brand-copy">
            <strong>CyberWatch</strong>
            <span>NETWORK INTELLIGENCE</span>
          </span>
        </a>
        <div className="topbar-status">
          <span className={`sensor-state ${connected ? "sensor-live" : ""}`} role="status" aria-live="polite">
            <span className="sensor-dot" />
            {connected ? "Sensor connected" : "Sensor offline"}
          </span>
          <span className="topbar-divider" aria-hidden="true" />
          <span className="local-label"><Radio size={14} /> LOCAL SENSOR</span>
        </div>
      </header>

      <main id="overview" className="dashboard-main">
        <section className="page-intro">
          <div>
            <p className="eyebrow"><span /> SECURITY OPERATIONS <span className="eyebrow-separator">/</span> OVERVIEW</p>
            <h1>Network overview</h1>
            <p className="intro-copy">
              {connected
                ? "Live traffic is flowing from your local sensor."
                : "Waiting for a connection to your local sensor."}
            </p>
          </div>
          <div className="session-chip">
            <span className="session-icon"><Activity size={16} /></span>
            <span><small>THIS SESSION</small><strong>{stats.total.toLocaleString()} <span>packets</span></strong></span>
          </div>
        </section>

        {streamError && <p className="status-error" role="alert">{streamError}</p>}

        <section className="stat-strip" aria-label="Session summary">
          <StatCard label="Packets observed" value={stats.total} accent="cyan" icon={<Activity size={17} />} detail="This session" />
          <StatCard label="No rule match" value={stats.threats.Normal} accent="green" icon={<ShieldCheck size={17} />} detail="Routine traffic" />
          <StatCard label="Needs review" value={stats.threats.Suspicious} accent="amber" icon={<AlertCircle size={17} />} detail="Heuristic match" />
          <StatCard label="Rule alerts" value={stats.threats.Suspicious + stats.threats.Malicious} accent="red" icon={<AlertTriangle size={17} />} detail="Review recommended" />
        </section>

        <section className="overview-grid" aria-label="Traffic and alert overview">
          <article className="card traffic-card">
            <div className="card-head">
              <div className="section-title">
                <span className="section-icon icon-accent"><Activity size={16} /></span>
                <div><h2>Traffic by protocol</h2><p>Observed during this session</p></div>
              </div>
              <span className="live-label"><span /> LIVE</span>
            </div>
            <div className="chart-area" role="img" aria-label="Captured packet count by protocol for this session">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} barCategoryGap="42%" margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <XAxis dataKey="name" tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} tickMargin={10} />
                  <YAxis tick={{ fill: "var(--text-muted)", fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} width={34} />
                  <Tooltip
                    cursor={{ fill: "var(--chart-hover)" }}
                    contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 10, fontSize: 12 }}
                    labelStyle={{ color: "var(--text-muted)" }}
                    itemStyle={{ color: "var(--text)" }}
                  />
                  <Bar dataKey="count" name="Packets" radius={[5, 5, 0, 0]} maxBarSize={54}>
                    {chartData.map((d) => <Cell key={d.name} fill={CHART_COLORS[d.name]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="protocol-legend" aria-label="Protocol totals">
              {chartData.map((item) => (
                <div className="protocol-total" key={item.name}>
                  <span className={`protocol-dot dot-${item.name.toLowerCase()}`} />
                  <span>{item.name}</span><strong>{item.count.toLocaleString()}</strong>
                </div>
              ))}
            </div>
          </article>

          <article className="card card-alerts">
            <div className="card-head">
              <div className="section-title">
                <span className="section-icon icon-danger"><AlertTriangle size={16} /></span>
                <div><h2>Recent rule alerts</h2><p>Latest heuristic matches</p></div>
              </div>
              {alerts.length > 0 && (
                <button className="icon-button" type="button" onClick={() => { setAlerts([]); setAlertsCleared(true); }} aria-label="Clear recent alerts" title="Clear recent alerts">
                  <Trash2 size={15} />
                </button>
              )}
            </div>
            <div className="alerts-list" aria-live="polite">
              {alerts.length === 0 ? (
                <div className="empty-alerts">
                  <span className="empty-icon"><ShieldCheck size={22} /></span>
                  <strong>{alertsCleared ? "Recent alerts cleared" : "No rule matches yet"}</strong>
                  <p>{alertsCleared ? "Session totals still include matches detected before clearing." : "Rule matches will appear here as traffic arrives."}</p>
                </div>
              ) : alerts.map((a, i) => (
                <div key={`${a.time}-${a.source}-${a.destination}-${i}`} className={`alert-item ${a.threat === "Malicious" ? "alert-mal" : "alert-sus"}`}>
                  <div className="alert-row">
                    <span className={`threat-tag ${threatClass(a.threat)}`}><ThreatIcon threat={a.threat} /> {a.threat}</span>
                    <time className="alert-time">{fmtTime(a.time)}</time>
                  </div>
                  <strong className="alert-type">{a.threat_type}</strong>
                  <div className="alert-ips">
                    <span className="ip-label">FROM</span><code>{a.source}</code>
                    <ArrowDownRight className="flow-icon" size={13} />
                    <span className="ip-label">TO</span><code>{a.destination}</code>
                  </div>
                  <div className="alert-foot">
                    <span>{a.protocol}{a.dst_port ? ` · PORT ${a.dst_port}` : ""}</span>
                    <span className={scoreClass(a.rule_score)}>Rule score {a.rule_score}/100</span>
                  </div>
                </div>
              ))}
            </div>
          </article>
        </section>

        <section className="card packets-card" aria-labelledby="packets-heading">
          <div className="packets-heading">
            <div className="section-title">
              <span className="section-icon icon-accent"><Radio size={16} /></span>
              <div>
                <h2 id="packets-heading">Packet activity</h2>
                <p>Most recent {Math.min(packets.length, 50)} records in this session</p>
              </div>
            </div>
            <div className="search-box">
              <Search size={15} aria-hidden="true" />
              <input
                type="search"
                placeholder="Search IP, protocol, rule…"
                value={packetSearch}
                onChange={(event) => setPacketSearch(event.target.value)}
                aria-label="Search packet activity"
              />
              {packetSearch && (
                <button type="button" className="search-clear" onClick={() => setPacketSearch("")} aria-label="Clear search">
                  <X size={14} />
                </button>
              )}
            </div>
          </div>
          <div className="table-toolbar">
            <div className="filter-tabs" role="group" aria-label="Filter packets">
              <button type="button" className={packetFilter === "all" ? "filter-active" : ""} aria-pressed={packetFilter === "all"} onClick={() => setPacketFilter("all")}>
                All traffic <span>{packets.length}</span>
              </button>
              <button type="button" className={packetFilter === "alerts" ? "filter-active" : ""} aria-pressed={packetFilter === "alerts"} onClick={() => setPacketFilter("alerts")}>
                Rule alerts <span>{stats.threats.Suspicious + stats.threats.Malicious}</span>
              </button>
            </div>
            <span className="table-count">Showing {visiblePackets.length} of {packets.length}</span>
          </div>
          <div className="table-wrap" role="region" aria-label="Packet activity" tabIndex={0}>
            <table className="tbl">
              <thead>
                <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Classification</th><th>Rule score</th></tr>
              </thead>
              <tbody>
                {visiblePackets.length === 0 ? (
                  <tr><td colSpan={6} className="empty-cell">
                    {packets.length === 0 ? (
                      <><span className="empty-icon"><Radio size={19} /></span><strong>No packet data yet</strong><span>{connected ? "Traffic will appear when the sensor observes packets." : "Connect the backend sensor to begin monitoring."}</span></>
                    ) : (
                      <><span className="empty-icon"><Search size={19} /></span><strong>No matching packets</strong><span>Try another search or switch to all traffic.</span></>
                    )}
                  </td></tr>
                ) : visiblePackets.map((packet, i) => (
                  <tr key={`${packet.time}-${packet.source}-${packet.destination}-${i}`} className={packet.threat !== "Normal" ? "row-alert" : ""}>
                    <td><time className="packet-time">{fmtTime(packet.time)}</time></td>
                    <td><code>{packet.source}</code></td>
                    <td><code>{packet.destination}{packet.dst_port ? <span className="destination-port">:{packet.dst_port}</span> : ""}</code></td>
                    <td><span className={`badge ${protocolClass(packet.protocol)}`}>{packet.protocol}</span></td>
                    <td>
                      <span className={`threat-tag ${threatClass(packet.threat)}`}>
                        <ThreatIcon threat={packet.threat} />
                        {packet.threat}
                        {packet.threat_type && packet.threat_type !== "None" && <span className="threat-type-label">{packet.threat_type}</span>}
                      </span>
                    </td>
                    <td><span className={`score-value ${scoreClass(packet.rule_score)}`}>{packet.rule_score}<small>/100</small></span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="table-footnote">Displaying the latest 50 packet records. Session counters include all packets received.</p>
        </section>

        <section className="card analyzer-card" aria-labelledby="analyzer-heading">
          <div className="analyzer-intro">
            <span className="section-icon icon-accent"><FileSearch size={17} /></span>
            <div>
              <h2 id="analyzer-heading">File indicator check</h2>
              <p>Basic metadata and byte-pattern heuristics — not a full malware scan.</p>
            </div>
          </div>
          <div className="analyzer-content">
            <div className="dropzone-wrap">
              <label
                htmlFor="file-inp"
                className={`dropzone ${dragOver ? "dropzone-over" : ""} ${file ? "dropzone-filled" : ""}`}
                onDragOver={(event) => { event.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
              >
                <span className="upload-icon"><UploadCloud size={19} /></span>
                <span className="upload-copy">
                  {file ? <><strong>{file.name}</strong><small>{fmtSize(file.size)} · Ready to check</small></> : <><strong>Choose a document</strong><small>or drag and drop · PDF, DOC, DOCX, PPT, PPTX · Max 50 MB</small></>}
                </span>
                <input
                  id="file-inp"
                  type="file"
                  accept=".pdf,.doc,.docx,.ppt,.pptx"
                  onChange={(event) => {
                    if (event.target.files[0]) handleFile(event.target.files[0]);
                    event.currentTarget.value = "";
                  }}
                />
              </label>
              {file && <button className="remove-file" type="button" aria-label="Remove selected file" onClick={(event) => { event.preventDefault(); event.stopPropagation(); setFile(null); setFileResult(null); setUploadError(""); }}><X size={15} /></button>}
            </div>
            <button className="btn-analyze" onClick={handleAnalyze} disabled={!file || uploading}>
              {uploading ? <span className="btn-spinner" /> : <FileSearch size={15} />}
              {uploading ? "Checking file…" : "Check file"}
            </button>
          </div>
          {uploadError && <p className="status-error" role="alert">{uploadError}</p>}
          {fileResult && (
            <div className={`result ${fileResult.status === "Malicious" ? "result-mal" : fileResult.status === "Suspicious" ? "result-sus" : "result-ok"}`} role="status">
              <div className="result-head">
                {fileResult.status === "No known indicators" ? <ShieldCheck size={17} /> : <AlertTriangle size={17} />}
                <strong>{fileResult.status}</strong>
                <span className="result-score">{fileResult.risk_score}<span className="result-max">/100</span></span>
              </div>
              <div className="result-file">{fileResult.filename}</div>
              {fileResult.file_size !== undefined && <div className="result-meta">File size · {fmtSize(fileResult.file_size)}</div>}
              {fileResult.flags?.length > 0 && (
                <ul className="result-flags">{fileResult.flags.map((flag, i) => <li key={`${i}-${flag}`}><AlertCircle size={12} /> {flag}</li>)}</ul>
              )}
            </div>
          )}
        </section>
      </main>
      <footer className="footer">
        <span><ShieldCheck size={14} /> Local network telemetry</span>
        <span>Rule scores are heuristic indicators, not probabilities.</span>
      </footer>
    </div>
  );
}

// ── Stat card ──────────────────────────────────────────────────────────────
function StatCard({ label, value, accent, icon, detail }) {
  return (
    <div className={`stat-card stat-${accent}`}>
      <div className="stat-top"><span className="stat-label">{label}</span><span className="stat-icon">{icon}</span></div>
      <strong className="stat-value">{value.toLocaleString()}</strong>
      <span className="stat-detail">{detail}</span>
    </div>
  );
}