"use client";

import {
  ArrowUpRight,
  Bot,
  Globe2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TrendingUp,
  Play,
  ExternalLink,
  ChevronRight,
} from "lucide-react";
import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { investigate, listInvestigations, getDemoScenarios, Report, DemoScenario } from "../lib/api";

const signalChecklist = [
  "Domain reputation mismatch",
  "Credential phishing language",
  "Suspicious redirect chain",
  "Requestless browser signal",
];

export default function Home() {
  const router = useRouter();
  const [reports, setReports] = useState<Report[]>([]);
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [runningDemo, setRunningDemo] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([listInvestigations(), getDemoScenarios()])
      .then(([reportsData, scenariosData]) => {
        setReports(reportsData);
        setScenarios(scenariosData);
      })
      .catch(() => setError("Live investigation data is unavailable."))
      .finally(() => setLoading(false));
  }, []);

  async function handleCheck(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!url.trim()) return;
    setChecking(true);
    setError("");
    try {
      const report = await investigate(url);
      router.push(`/investigations/${report.id}`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The check failed.");
      setChecking(false);
    }
  }

  async function runDemoScenario(scenario: DemoScenario) {
    setRunningDemo(scenario.id);
    setError("");
    try {
      const report = await investigate(scenario.url);
      router.push(`/investigations/${report.id}`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The demo check failed.");
      setRunningDemo(null);
    }
  }

  const highRisk = reports.filter((report) => ["HIGH", "CRITICAL", "STOP"].includes(report.classification)).length;
  const confidence = reports.length
    ? Math.round(reports.reduce((total, report) => total + report.confidence, 0) / reports.length)
    : 0;
  const summary = [
    { label: "Investigations", value: String(reports.length) },
    { label: "High-risk URLs", value: String(highRisk) },
    { label: "Evidence captured", value: String(reports.reduce((total, report) => total + report.evidence.length, 0)) },
    { label: "Avg. confidence", value: `${confidence}%` },
  ];

  const riskColor: Record<string, string> = {
    LOW: "low",
    MEDIUM: "moderate",
    HIGH: "high",
    CRITICAL: "stop",
    STOP: "stop",
    TRUSTED: "low",
    CAUTION: "moderate",
    HIGH_RISK: "high",
  };

  return (
    <main className="dashboard-shell">
      <section className="hero-panel real">
        <div className="hero-copy">
          <div className="eyebrow">
            <ShieldCheck size={14} />
            Digital threat intelligence
          </div>
          <h1>See the risk before a user clicks.</h1>
          <p>
            M-PHISH X reviews URL reputation, page signals, identity markers, and
            redirect behavior to keep risky websites from slipping through.
          </p>

          <form className="hero-actions" onSubmit={handleCheck}>
            <input
              className="hero-input"
              aria-label="Website URL to investigate"
              placeholder="Paste a website URL"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
            />
            <button className="primary-action" disabled={checking}>
              {checking ? "Analyzing..." : "Run investigation"}
            </button>
            <button className="secondary-action" type="button" onClick={() => router.push("/investigations")}>
              View history
            </button>
          </form>
          {error && <p className="form-error" role="alert">{error}</p>}
        </div>

        <div className="hero-visual">
          <div className="status-row">
            <span>Threat posture</span>
            <span className="pill active">Protected</span>
          </div>

          <div className="spark-panel">
            <div className="spark-overlay">
              <span className="signal-dot good" />
              <span className="signal-dot warn" />
              <span className="signal-dot critical" />
            </div>
          </div>

          <div className="mini-card">
            <div className="mini-copy">
              <span className="mini-label">Current detection</span>
              <strong>Low compromise drift</strong>
            </div>
            <TrendingUp size={18} />
          </div>
        </div>
      </section>

      <section className="summary-grid">
        {summary.map((item) => (
          <div className="summary-card" key={item.label}>
            <span className="summary-label">{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </section>

      <section className="content-grid">
        <div className="panel-card">
          <div className="panel-header-row">
            <div>
              <div className="section-kicker">Live signals</div>
              <h2>Priority checks</h2>
            </div>
            <button className="ghost-button">
              <ArrowUpRight size={16} />
              Advanced view
            </button>
          </div>

          <ul className="signal-list">
            {signalChecklist.map((signal) => (
              <li key={signal}>
                <div className="signal-icon">
                  <ShieldAlert size={14} />
                </div>
                <span>{signal}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="panel-card">
          <div className="panel-header-row">
            <div>
              <div className="section-kicker">Recent activity</div>
              <h2>Investigation queue</h2>
            </div>
          </div>

          <div className="queue-list">
            {loading && <div className="empty">Loading investigation records...</div>}
            {!loading && !reports.length && <div className="empty">No investigations yet. Run a check to create the first record.</div>}
            {!loading && reports.slice(0, 4).map((report) => (
              <div className="queue-item" key={report.id}>
                <div>
                  <div className="host-name">{report.hostname}</div>
                  <div className="host-subtle">{report.evidence.length} evidence signals captured</div>
                </div>
                <div className="queue-meta">
                  <span className={`risk-tag ${report.classification.toLowerCase()}`}>
                    {report.classification}
                  </span>
                  <strong>{report.risk_score}</strong>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {scenarios.length > 0 && (
        <section className="surface" style={{ marginTop: 12 }}>
          <div className="panel-header-row">
            <div>
              <div className="section-kicker">Verified walkthroughs</div>
              <h2>Demo scenarios with deep checks</h2>
            </div>
          </div>
          <p className="subtle" style={{ marginBottom: 18 }}>
            Pre-configured safe fixtures that exercise every detection layer. Click "Run deep check" to launch a full
            investigation and view the detailed forensic report.
          </p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 16 }}>
            {scenarios.map((scenario) => (
              <div
                key={scenario.id}
                className="surface"
                style={{ padding: 20, border: "1px solid var(--line)", borderRadius: "var(--radius-lg)" }}
              >
                <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
                  <div style={{ flex: 1 }}>
                    <h3 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 650 }}>{scenario.title}</h3>
                    <p className="subtle" style={{ marginTop: 4, fontSize: "0.82rem", lineHeight: 1.5 }}>{scenario.description}</p>
                  </div>
                  <span className={`risk-pill ${riskColor[scenario.expected_state] || "unknown"}`} style={{ flexShrink: 0 }}>
                    {scenario.expected_state}
                  </span>
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                  <button
                    className="primary-action"
                    style={{ flex: 1, minHeight: 40, padding: "0 16px", fontSize: "0.8rem" }}
                    onClick={() => runDemoScenario(scenario)}
                    disabled={runningDemo === scenario.id}
                  >
                    {runningDemo === scenario.id ? (
                      <>
                        <span style={{ display: "inline-block", width: 14, height: 14, border: "2px solid currentColor", borderRightColor: "transparent", borderRadius: "50%", animation: "spin 720ms linear infinite", marginRight: 8 }} />
                        Running deep check...
                      </>
                    ) : (
                      <>
                        <Play size={14} style={{ marginRight: 6 }} />
                        Run deep check
                      </>
                    )}
                  </button>
                  <button
                    className="secondary-action"
                    style={{ minHeight: 40, padding: "0 16px", fontSize: "0.8rem" }}
                    onClick={() => router.push(`/investigations`)}
                    title="View all investigations"
                  >
                    <ExternalLink size={14} style={{ marginRight: 6 }} />
                    History
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="insights-row">
        <div className="insight-card">
          <div className="insight-icon purple">
            <Bot size={18} />
          </div>
          <div>
            <div className="section-kicker">AI assistance</div>
            <h3>Evidence phrasing</h3>
          </div>
        </div>
        <div className="insight-card">
          <div className="insight-icon cyan">
            <Globe2 size={18} />
          </div>
          <div>
            <div className="section-kicker">Context layer</div>
            <h3>Domain + page + behavior</h3>
          </div>
        </div>
        <div className="insight-card">
          <div className="insight-icon amber">
            <Sparkles size={18} />
          </div>
          <div>
            <div className="section-kicker">Safety model</div>
            <h3>Transparent, explainable scoring</h3>
          </div>
        </div>
      </section>
    </main>
  );
}// force rebuild
