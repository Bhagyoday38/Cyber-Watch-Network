import React, { useEffect, useState, useRef } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import {
  ShieldAlert, Activity, AlertTriangle, FileSearch,
  UploadCloud, CheckCircle, ShieldCheck, Wifi, WifiOff,
  AlertCircle,
} from "lucide-react";

// ── Helpers ────────────────────────────────────────────────────────────────

const protocolClass = (p) =>
  ({ TCP: "badge-tcp", UDP: "badge-udp", IP: "badge-ip" }[p] ?? "badge-default");

const likelihoodClass = (str) => {
  const v = parseInt(str);
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

// ── Chart colours ──────────────────────────────────────────────────────────
const CHART_COLORS = {
  TCP: "var(--c-cyan)",
  UDP: "var(--c-purple)",
  IP: "var(--c-green)",
};

// ── App ────────────────────────────────────────────────────────────────────

export default function App() {
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);

  // File analyzer
  const [file, setFile] = useState(null);
  const [fileResult, setFileResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  // Stats
  const protocolCounts = packets.reduce(
    (acc, p) => { acc[p.protocol] = (acc[p.protocol] || 0) + 1; return acc; },
    { TCP: 0, UDP: 0, IP: 0 }
  );
  const threatCounts = packets.reduce(
    (acc, p) => { acc[p.threat] = (acc[p.threat] || 0) + 1; return acc; },
    { Normal: 0, Suspicious: 0, Malicious: 0 }
  );

  // ── WebSocket ─────────────────────────────────────────────────────────────
  useEffect(() => {
    let ws;
    const connect = () => {
      ws = new WebSocket("ws://localhost:8000/ws/packets");
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);

      ws.onmessage = ({ data }) => {
        const pkt = JSON.parse(data);
        setPackets((prev) => [...prev.slice(-49), pkt]);
        if (pkt.threat !== "Normal") {
          setAlerts((prev) => [pkt, ...prev.slice(0, 9)]);
        }
      };

      ws.onerror = () => setConnected(false);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000); // auto-reconnect
      };
    };
    connect();
    return () => ws?.close();
  }, []);

  // ── File upload ───────────────────────────────────────────────────────────
  const handleFile = (f) => { setFile(f); setFileResult(null); };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  };

  const handleAnalyze = async () => {
    if (!file) return;
    setUploading(true);
    setFileResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch("http://localhost:8000/upload-file", { method: "POST", body: fd });
      setFileResult(await res.json());
    } catch (e) {
      console.error(e);
    } finally {
      setUploading(false);
    }
  };

  const chartData = [
    { name: "TCP", count: protocolCounts.TCP },
    { name: "UDP", count: protocolCounts.UDP },
    { name: "IP", count: protocolCounts.IP },
  ];

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="root">

      {/* ── Header ── */}
      <header className="header">
        <div className="header-brand">
          <ShieldAlert className="header-icon" />
          <span className="header-title">CyberWatch</span>
          <span className="header-sub">Network Intelligence Dashboard</span>
        </div>
        <div className={`conn-badge ${connected ? "conn-ok" : "conn-off"}`}>
          {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
          {connected ? "Live" : "Offline"}
        </div>
      </header>

      {/* ── Stat strip ── */}
      <div className="stat-strip">
        <StatCard label="Packets captured" value={packets.length} accent="cyan" />
        <StatCard label="Normal" value={threatCounts.Normal} accent="green" />
        <StatCard label="Suspicious" value={threatCounts.Suspicious} accent="amber" />
        <StatCard label="Malicious" value={threatCounts.Malicious} accent="red" />
      </div>

      {/* ── Main grid ── */}
      <div className="grid">

        {/* Left column */}
        <div className="col-main">

          {/* Traffic chart */}
          <div className="card">
            <div className="card-head">
              <Activity size={15} className="icon-accent" />
              <h2>Protocol Distribution</h2>
              <span className="card-meta">{packets.length} packets</span>
            </div>
            <div style={{ height: 200 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} barCategoryGap="35%">
                  <XAxis dataKey="name" tick={{ fill: "var(--text-muted)", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: "rgba(255,255,255,0.04)" }}
                    contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: "var(--text-muted)" }}
                    itemStyle={{ color: "var(--text)" }}
                  />
                  <Bar dataKey="count" name="Packets" radius={[6, 6, 0, 0]}>
                    {chartData.map((d) => (
                      <Cell key={d.name} fill={CHART_COLORS[d.name]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Live packets table */}
          <div className="card">
            <div className="card-head">
              <h2>Live Packets</h2>
              <span className="card-meta">Last {Math.min(packets.length, 50)}</span>
            </div>
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Threat</th>
                    <th>Likelihood</th>
                  </tr>
                </thead>
                <tbody>
                  {packets.length === 0 ? (
                    <tr><td colSpan={6} className="empty">Waiting for packets…</td></tr>
                  ) : (
                    [...packets].reverse().map((p, i) => (
                      <tr key={i} className={p.threat !== "Normal" ? "row-alert" : ""}>
                        <td><code>{p.source}</code></td>
                        <td><code>{p.destination}</code></td>
                        <td><code className="port">{p.dst_port ?? "—"}</code></td>
                        <td><span className={`badge ${protocolClass(p.protocol)}`}>{p.protocol}</span></td>
                        <td>
                          <span className={`threat-tag ${threatClass(p.threat)}`}>
                            <ThreatIcon threat={p.threat} />
                            {p.threat}
                            {p.threat_type && p.threat_type !== "None" && (
                              <span className="threat-type-label">{p.threat_type}</span>
                            )}
                          </span>
                        </td>
                        <td className={likelihoodClass(p.attack_likelihood)}>
                          {p.attack_likelihood}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right column */}
        <div className="col-side">

          {/* Alerts */}
          <div className="card card-alerts">
            <div className="card-head">
              <AlertTriangle size={15} className="icon-danger" />
              <h2>Threat Alerts</h2>
              {alerts.length > 0 && <span className="alert-count">{alerts.length}</span>}
            </div>
            <div className="alerts-list">
              {alerts.length === 0 ? (
                <div className="empty-alerts">
                  <ShieldCheck size={28} className="empty-shield" />
                  <p>No threats detected</p>
                </div>
              ) : alerts.map((a, i) => (
                <div key={i} className={`alert-item ${a.threat === "Malicious" ? "alert-mal" : "alert-sus"}`}>
                  <div className="alert-row">
                    <span className={`threat-tag ${threatClass(a.threat)}`}>
                      <ThreatIcon threat={a.threat} /> {a.threat}
                    </span>
                    <span className={`badge ${protocolClass(a.protocol)}`}>{a.protocol}</span>
                  </div>
                  {a.threat_type && a.threat_type !== "None" && (
                    <div className="alert-type">{a.threat_type}</div>
                  )}
                  <div className="alert-ips">
                    <span className="ip-label">SRC</span><code>{a.source}</code>
                    <span className="ip-label">DST</span><code>{a.destination}</code>
                    {a.dst_port && <><span className="ip-label">PORT</span><code>{a.dst_port}</code></>}
                  </div>
                  <div className="alert-foot">
                    <span>Likelihood</span>
                    <span className={likelihoodClass(a.attack_likelihood)}>{a.attack_likelihood}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* File analyzer */}
          <div className="card">
            <div className="card-head">
              <FileSearch size={15} className="icon-accent" />
              <h2>File Threat Analyzer</h2>
            </div>
            <p className="card-desc">Upload a file to scan for malicious indicators.</p>

            {/* Drop zone */}
            <label
              htmlFor="file-inp"
              className={`dropzone ${dragOver ? "dropzone-over" : ""} ${file ? "dropzone-filled" : ""}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
            >
              <UploadCloud size={22} className="drop-icon" />
              {file ? (
                <>
                  <p className="drop-filename">{file.name}</p>
                  <p className="drop-size">{fmtSize(file.size)}</p>
                </>
              ) : (
                <>
                  <p><strong>Click to upload</strong> or drag & drop</p>
                  <p className="drop-hint">Any file type • Max 50 MB</p>
                </>
              )}
              <input id="file-inp" type="file" onChange={(e) => e.target.files[0] && handleFile(e.target.files[0])} style={{ display: "none" }} />
            </label>

            <button
              className={`btn-analyze ${(!file || uploading) ? "btn-disabled" : ""}`}
              onClick={handleAnalyze}
              disabled={!file || uploading}
            >
              {uploading ? (
                <span className="btn-spinner" />
              ) : (
                <FileSearch size={14} />
              )}
              {uploading ? "Analyzing…" : "Analyze File"}
            </button>

            {/* Result */}
            {fileResult && (
              <div className={`result ${fileResult.status === "Malicious" ? "result-mal" : fileResult.status === "Suspicious" ? "result-sus" : "result-ok"}`}>
                <div className="result-head">
                  {fileResult.status === "Safe"
                    ? <ShieldCheck size={16} />
                    : <AlertTriangle size={16} />}
                  <strong>{fileResult.status}</strong>
                  <span className="result-score">{fileResult.risk_score}<span className="result-max">/100</span></span>
                </div>
                <div className="result-file">{fileResult.filename}</div>
                {fileResult.file_size !== undefined && (
                  <div className="result-meta">Size: {fmtSize(fileResult.file_size)}</div>
                )}
                {fileResult.flags?.length > 0 && (
                  <ul className="result-flags">
                    {fileResult.flags.map((f, i) => (
                      <li key={i}><AlertCircle size={11} /> {f}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}

// ── Stat card ──────────────────────────────────────────────────────────────
function StatCard({ label, value, accent }) {
  return (
    <div className={`stat-card stat-${accent}`}>
      <span className="stat-value">{value.toLocaleString()}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}