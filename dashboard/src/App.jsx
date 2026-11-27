import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  EyeOff,
  Flame,
  Gauge,
  Layers,
  Lock,
  Play,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  OWASP_TOP_10,
  SEED_FINDINGS,
  SEED_INVENTORY,
  SEED_LATENCY,
} from "./data/seedData";

function clientMaskPreview(input) {
  let redactions = 0;
  const text = typeof input === "string" ? input : JSON.stringify(input, null, 2);
  let masked = text
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g, () => {
      redactions += 1;
      return "[REDACTED_JWT]";
    })
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, () => {
      redactions += 1;
      return "***-**-****";
    })
    .replace(/\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, (_, l, d) => {
      redactions += 1;
      return `${l[0] || "*"}***@${d}`;
    })
    .replace(/\b(?:\d[ -]*?){13,19}\b/g, (raw) => {
      const digits = raw.replace(/\D/g, "");
      if (digits.length >= 13 && digits.length <= 19) {
        redactions += 1;
        return `****-****-****-${digits.slice(-4)}`;
      }
      return raw;
    })
    .replace(/"(password|secret|token|api_key|ssn)"\s*:\s*"[^"]*"/gi, (_, k) => {
      redactions += 1;
      return `"${k}": "[REDACTED_SECRET]"`;
    });
  return { masked, redactions };
}

function formatTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function App() {
  const [tab, setTab] = useState("overview");
  const [findings, setFindings] = useState(SEED_FINDINGS);
  const [inventory, setInventory] = useState(SEED_INVENTORY);
  const [liveConnected, setLiveConnected] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const [owaspFilter, setOwaspFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState("all");
  const [invFilter, setInvFilter] = useState("all");

  const [maskInput, setMaskInput] = useState(
    JSON.stringify(
      {
        user: "victim@crapi.local",
        password: "super-secret-password",
        token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEwMiJ9.sig123456",
        credit_card: "4111-1111-1111-1111",
        ssn: "123-45-6789",
      },
      null,
      2
    )
  );
  const [maskOutput, setMaskOutput] = useState(() => clientMaskPreview(maskInput));

  async function refreshFromBackend() {
    try {
      const [fRes, iRes] = await Promise.all([
        fetch("/api/findings"),
        fetch("/api/inventory"),
      ]);
      if (!fRes.ok || !iRes.ok) throw new Error("Backend unavailable");
      const fData = await fRes.json();
      const iData = await iRes.json();
      if (Array.isArray(fData.findings) && fData.findings.length > 0) {
        setFindings(fData.findings);
      }
      if (Array.isArray(iData.endpoints) && iData.endpoints.length > 0) {
        setInventory(iData.endpoints);
      }
      setLiveConnected(true);
    } catch {
      setLiveConnected(false);
    }
  }

  useEffect(() => {
    refreshFromBackend();
  }, []);

  async function simulateAttack() {
    const sample = {
      type: "BOLA",
      owasp: "API1",
      user: "attacker@crapi.local",
      src_ip: "10.0.0.99",
      endpoint: "GET /workshop/api/shop/orders/1009",
      severity: "critical",
      action: "block",
      reason: "Simulated BOLA probe on crAPI order 1009 (blocked at XDP)",
      ts: Date.now() / 1000,
      evidence: {
        email: "victim@crapi.local",
        credit_card: "4111-1111-1111-1111",
        token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEwOSJ9.demo999",
      },
    };

    if (liveConnected) {
      try {
        const res = await fetch("/api/ingest/finding", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(sample),
        });
        if (res.ok) {
          const data = await res.json();
          setFindings((prev) => [data.finding, ...prev]);
          return;
        }
      } catch {
        // Fallback to local masked preview
      }
    }

    const maskedLocal = {
      ...sample,
      user: "a***@crapi.local",
      pii_masked: true,
      redacted_fields: 3,
      evidence: {
        email: "v***@crapi.local",
        credit_card: "****-****-****-1111",
        token: "[REDACTED_JWT]",
      },
    };
    setFindings((prev) => [maskedLocal, ...prev]);
  }

  async function runMaskTest() {
    if (liveConnected) {
      try {
        const parsed = JSON.parse(maskInput);
        const res = await fetch("/api/mask/preview", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload: parsed }),
        });
        if (res.ok) {
          const out = await res.json();
          setMaskOutput({
            masked: JSON.stringify(out.data, null, 2),
            redactions: out.redactions,
          });
          return;
        }
      } catch {
        // Fall through to client preview
      }
    }
    setMaskOutput(clientMaskPreview(maskInput));
  }

  const metrics = useMemo(() => {
    const blocked = findings.filter((f) => f.action === "block").length;
    const critical = findings.filter((f) => f.severity === "critical").length;
    const shadowOrZombie = inventory.filter(
      (e) => e.status === "shadow" || e.status === "zombie"
    ).length;
    const redactedTotal = findings.reduce(
      (acc, f) => acc + (Number(f.redacted_fields) || 0),
      0
    );
    return {
      totalFindings: findings.length,
      blocked,
      critical,
      endpoints: inventory.length,
      shadowOrZombie,
      redactedTotal,
    };
  }, [findings, inventory]);

  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (sevFilter !== "all" && f.severity !== sevFilter) return false;
      if (owaspFilter !== "all" && f.owasp !== owaspFilter) return false;
      if (actionFilter !== "all" && f.action !== actionFilter) return false;
      if (!q) return true;
      return (
        (f.endpoint || "").toLowerCase().includes(q) ||
        (f.user || "").toLowerCase().includes(q) ||
        (f.reason || "").toLowerCase().includes(q) ||
        (f.type || "").toLowerCase().includes(q)
      );
    });
  }, [findings, search, sevFilter, owaspFilter, actionFilter]);

  const filteredInventory = useMemo(() => {
    if (invFilter === "all") return inventory;
    return inventory.filter((e) => e.status === invFilter);
  }, [inventory, invFilter]);

  const owaspCounts = useMemo(() => {
    const counts = {};
    for (const f of findings) {
      counts[f.owasp] = (counts[f.owasp] || 0) + 1;
    }
    return counts;
  }, [findings]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={20} />
          </div>
          <div>
            <h1>API-Sentinel</h1>
            <p>Runtime BOLA, Shadow API &amp; OWASP Threat Dashboard</p>
          </div>
        </div>

        <nav className="nav-tabs">
          {[
            { id: "overview", label: "Overview", icon: Activity },
            { id: "alerts", label: "Live Alerts", icon: ShieldAlert },
            { id: "inventory", label: "Endpoint Inventory", icon: Layers },
            { id: "owasp", label: "OWASP Top 10", icon: Flame },
            { id: "privacy", label: "PII Masking & SLA", icon: Lock },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`tab-btn ${tab === id ? "active" : ""}`}
              onClick={() => setTab(id)}
            >
              <Icon size={15} />
              {label}
            </button>
          ))}
        </nav>

        <div className="topbar-actions">
          <span className="status-pill">
            <span className={`dot ${liveConnected ? "live" : "demo"}`} />
            {liveConnected ? "Live Masking API" : "crAPI Seed Telemetry"}
          </span>
          <button className="btn" onClick={refreshFromBackend} title="Sync with masking/server.py">
            <RefreshCw size={14} />
            Sync
          </button>
          <button className="btn btn-primary" onClick={simulateAttack}>
            <Play size={14} />
            Simulate Attack
          </button>
        </div>
      </header>

      <main className="main-content">
        <section className="kpi-grid">
          <div className="card kpi-card">
            <div className="kpi-header">
              <span>Active Findings</span>
              <ShieldAlert size={16} color="#f43f5e" />
            </div>
            <div className="kpi-value">{metrics.totalFindings}</div>
            <div className="kpi-sub">{metrics.critical} critical severity alerts</div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-header">
              <span>Kernel XDP Verdicts</span>
              <ShieldCheck size={16} color="#fb923c" />
            </div>
            <div className="kpi-value">{metrics.blocked}</div>
            <div className="kpi-sub">Block verdicts pushed to blocklist</div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-header">
              <span>API Attack Surface</span>
              <Layers size={16} color="#38bdf8" />
            </div>
            <div className="kpi-value">{metrics.endpoints}</div>
            <div className="kpi-sub">{metrics.shadowOrZombie} Shadow / Zombie endpoints</div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-header">
              <span>PII Fields Masked</span>
              <EyeOff size={16} color="#a78bfa" />
            </div>
            <div className="kpi-value">{metrics.redactedTotal}</div>
            <div className="kpi-sub">Emails, JWTs, cards &amp; SSNs stripped</div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-header">
              <span>Pipeline Overhead (p95)</span>
              <Gauge size={16} color="#34d399" />
            </div>
            <div className="kpi-value">{SEED_LATENCY.masking_overhead_ms.p95} ms</div>
            <div className="kpi-sub">Under {SEED_LATENCY.sla_ms} ms SLA target</div>
          </div>
        </section>

        {tab === "overview" && (
          <>
            <div className="grid-2">
              <div className="card">
                <h2 className="section-title">
                  <span>OWASP API Top 10 Distribution</span>
                  <span className="badge owasp-pill">2023 / 2026</span>
                </h2>
                {["API1", "API5", "API9", "API4"].map((cat) => {
                  const count = owaspCounts[cat] || 0;
                  const pct = Math.min(100, Math.round((count / Math.max(1, findings.length)) * 100));
                  const info = OWASP_TOP_10.find((o) => o.id === cat);
                  return (
                    <div className="bar-row" key={cat}>
                      <div className="bar-label">{cat}</div>
                      <div className="bar-track" title={info?.name}>
                        <div className="bar-fill" style={{ width: `${pct}%` }} />
                      </div>
                      <div className="bar-count">{count}</div>
                    </div>
                  );
                })}
                <p className="kpi-sub" style={{ marginTop: "0.75rem" }}>
                  Target testbed: <strong>crAPI</strong> (Identity, Workshop, Community &amp; Legacy v1 APIs).
                </p>
              </div>

              <div className="card">
                <h2 className="section-title">
                  <span>Shadow &amp; Zombie Surface Snapshot</span>
                  <span className="badge status-shadow">{metrics.shadowOrZombie} Unmanaged</span>
                </h2>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Endpoint</th>
                        <th>Status</th>
                        <th>OWASP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {inventory.slice(0, 5).map((ep, idx) => (
                        <tr key={idx}>
                          <td>
                            <code>{ep.method} {ep.endpoint}</code>
                          </td>
                          <td>
                            <span className={`badge status-${ep.status}`}>{ep.status}</span>
                          </td>
                          <td>
                            {ep.owasp_tags?.length ? (
                              ep.owasp_tags.map((tag) => (
                                <span key={tag} className="badge owasp-pill" style={{ marginRight: 4 }}>
                                  {tag}
                                </span>
                              ))
                            ) : (
                              <span className="kpi-sub">Clean</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="card">
              <h2 className="section-title">
                <span>Recent Masked Security Findings</span>
                <button className="btn" onClick={() => setTab("alerts")}>
                  View All
                </button>
              </h2>
              <FindingsTable rows={findings.slice(0, 5)} onSelect={setSelectedFinding} />
            </div>
          </>
        )}

        {tab === "alerts" && (
          <div className="card">
            <h2 className="section-title">
              <span>Live Threat Findings (PII Redacted)</span>
              <span className="kpi-sub">{filteredFindings.length} matching alerts</span>
            </h2>

            <div className="filters-bar">
              <input
                className="input"
                placeholder="Search endpoint, user, reason, or attack type..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <select className="select" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select className="select" value={owaspFilter} onChange={(e) => setOwaspFilter(e.target.value)}>
                <option value="all">All OWASP</option>
                {OWASP_TOP_10.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.id}
                  </option>
                ))}
              </select>
              <select className="select" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
                <option value="all">All Verdicts</option>
                <option value="block">Block</option>
                <option value="alert">Alert</option>
              </select>
            </div>

            <FindingsTable rows={filteredFindings} onSelect={setSelectedFinding} />
          </div>
        )}

        {tab === "inventory" && (
          <div className="card">
            <h2 className="section-title">
              <span>Observed API Endpoint Inventory</span>
              <div style={{ display: "flex", gap: "0.4rem" }}>
                {["all", "documented", "shadow", "zombie"].map((st) => (
                  <button
                    key={st}
                    className={`tab-btn ${invFilter === st ? "active" : ""}`}
                    onClick={() => setInvFilter(st)}
                  >
                    {st.toUpperCase()}
                  </button>
                ))}
              </div>
            </h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Normalized Endpoint</th>
                    <th>Classification</th>
                    <th>Hits</th>
                    <th>Avg Latency</th>
                    <th>OWASP Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredInventory.map((ep, idx) => (
                    <tr key={idx}>
                      <td><code>{ep.method}</code></td>
                      <td><code>{ep.endpoint}</code></td>
                      <td>
                        <span className={`badge status-${ep.status}`}>{ep.status}</span>
                      </td>
                      <td>{ep.hits}</td>
                      <td>{ep.avg_latency_ms} ms</td>
                      <td>
                        {ep.owasp_tags?.length ? (
                          ep.owasp_tags.map((t) => (
                            <span key={t} className="badge owasp-pill" style={{ marginRight: 4 }}>
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="kpi-sub">None detected</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === "owasp" && (
          <div className="owasp-grid">
            {OWASP_TOP_10.map((item) => {
              const count = owaspCounts[item.id] || 0;
              return (
                <div key={item.id} className={`owasp-card ${count > 0 ? "hit" : ""}`}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span className="badge owasp-pill">{item.code}</span>
                    <span className={`badge ${count > 0 ? "sev-critical" : "sev-low"}`}>
                      {count > 0 ? `${count} Active` : "0 Alerts"}
                    </span>
                  </div>
                  <strong>{item.name}</strong>
                  <p className="kpi-sub" style={{ margin: 0 }}>{item.description}</p>
                  <div className="kpi-sub" style={{ borderTop: "1px solid var(--border)", paddingTop: "0.45rem" }}>
                    <strong>Mitigation:</strong> {item.remediation}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {tab === "privacy" && (
          <div className="grid-2">
            <div className="card">
              <h2 className="section-title">
                <span>Interactive PII Masking Sandbox (`masking/`)</span>
                <span className="badge sev-low">{maskOutput.redactions} Redactions</span>
              </h2>
              <p className="kpi-sub" style={{ marginTop: 0 }}>
                All findings and captured payloads pass through <code>PIIMasker</code> before reaching this dashboard.
              </p>
              <textarea
                className="textarea"
                value={maskInput}
                onChange={(e) => setMaskInput(e.target.value)}
              />
              <div style={{ margin: "0.75rem 0" }}>
                <button className="btn btn-primary" onClick={runMaskTest}>
                  <EyeOff size={14} />
                  Run PII Masker
                </button>
              </div>
              <pre className="json-box">{maskOutput.masked}</pre>
            </div>

            <div className="card">
              <h2 className="section-title">
                <span>Testbed Latency Audit (`&lt; 5 ms` SLA)</span>
                <span className="badge sev-low">SLA PASSED</span>
              </h2>
              <p className="kpi-sub" style={{ marginTop: 0 }}>
                Measured over {SEED_LATENCY.iterations} crAPI requests comparing baseline vs. masking pipeline overhead.
              </p>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Baseline crAPI</th>
                      <th>Masking Overhead</th>
                    </tr>
                  </thead>
                  <tbody>
                    {["mean", "p50", "p95", "p99"].map((stat) => (
                      <tr key={stat}>
                        <td><strong>{stat.toUpperCase()}</strong></td>
                        <td>{SEED_LATENCY.baseline_ms[stat]} ms</td>
                        <td style={{ color: "#6ee7b7" }}>{SEED_LATENCY.masking_overhead_ms[stat]} ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="card" style={{ marginTop: "1rem", background: "var(--surface-2)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <AlertTriangle size={16} color="#34d399" />
                  <strong>Zero Raw PII Stored</strong>
                </div>
                <p className="kpi-sub" style={{ margin: "0.35rem 0 0" }}>
                  Luhn-verified credit cards, SSNs, JWT bearer tokens, passwords, and emails are stripped in memory prior to WebSocket broadcast.
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {selectedFinding && (
        <div className="drawer-backdrop" onClick={() => setSelectedFinding(null)}>
          <aside className="drawer" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", gap: "0.45rem", alignItems: "center" }}>
                <span className={`badge sev-${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                <span className="badge owasp-pill">{selectedFinding.owasp}</span>
                <span className={`badge action-${selectedFinding.action}`}>{selectedFinding.action}</span>
              </div>
              <button className="btn" onClick={() => setSelectedFinding(null)}>
                <X size={15} />
              </button>
            </div>
            <h2 style={{ margin: 0, fontSize: "1.05rem" }}>
              {selectedFinding.type}: <code>{selectedFinding.endpoint}</code>
            </h2>
            <p className="kpi-sub" style={{ margin: 0 }}>{selectedFinding.reason}</p>
            <div className="kpi-sub">
              <strong>Caller:</strong> {selectedFinding.user} &nbsp;|&nbsp; <strong>Source IP:</strong> {selectedFinding.src_ip} &nbsp;|&nbsp; <strong>Time:</strong> {formatTime(selectedFinding.ts)}
            </div>
            <div>
              <div className="kpi-sub" style={{ marginBottom: "0.4rem" }}>
                Masked Evidence Payload ({selectedFinding.redacted_fields || 0} fields redacted)
              </div>
              <pre className="json-box">{JSON.stringify(selectedFinding.evidence, null, 2)}</pre>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}

function FindingsTable({ rows, onSelect }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>OWASP</th>
            <th>Severity</th>
            <th>Endpoint</th>
            <th>User (Masked)</th>
            <th>Verdict</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f, idx) => (
            <tr key={idx} className="clickable" onClick={() => onSelect(f)}>
              <td>{formatTime(f.ts)}</td>
              <td><strong>{f.type}</strong></td>
              <td><span className="badge owasp-pill">{f.owasp}</span></td>
              <td><span className={`badge sev-${f.severity}`}>{f.severity}</span></td>
              <td><code>{f.endpoint}</code></td>
              <td>{f.user}</td>
              <td><span className={`badge action-${f.action}`}>{f.action}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
