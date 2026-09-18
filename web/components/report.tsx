"use client";
import { useState } from "react";
import {
  AlertCircle,
  ArrowUpRight,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  ExternalLink,
  Fingerprint,
  GitBranch,
  HelpCircle,
  Info,
  Layers3,
  Lock,
  MousePointer2,
  Network,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  UserCheck,
} from "lucide-react";
import { Evidence, Graph, Report as ReportData } from "../lib/api";
import { RiskBadge, TrustBadge, riskTone } from "./risk";

function formatDate(value?: string) {
  return value
    ? new Date(value).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Recent";
}

export function EvidenceList({ items }: { items: Evidence[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  return (
    <div className="evidence-list">
      {items.length ? (
        items.map((item) => (
          <button
            className={`evidence-item ${selected === item.id ? "selected" : ""}`}
            key={item.id}
            onClick={() => setSelected(selected === item.id ? null : item.id)}
          >
            <span className={`evidence-mark ${riskTone(item.severity)}`}>
              <Info size={15} />
            </span>
            <span className="evidence-copy">
              <span className="evidence-meta">
                {item.category} <i>{item.severity}</i>
              </span>
              <strong>{item.title}</strong>
              <span className="evidence-description">{item.description}</span>
              <span className="evidence-source">
                {item.source || "Deterministic analyzer"} ·{" "}
                {Math.round(item.confidence * 100)}% confidence
              </span>
              {selected === item.id && (
                <span className="evidence-detail">
                  Signal observed by <b>{item.source || "the investigation engine"}</b>
                  . Contributed <b>+{item.weight}</b> to evidentiary assessment.
                </span>
              )}
            </span>
            <span className="evidence-weight">+{item.weight}</span>
          </button>
        ))
      ) : (
        <div className="empty-state">No anomalous evidence recorded.</div>
      )}
    </div>
  );
}

export function Timeline({ events }: { events: ReportData["events"] }) {
  return (
    <div className="timeline">
      {events && events.length ? (
        events.map((event, index) => (
          <div className="timeline-event" key={`${event.event_type}-${index}`}>
            <span className="timeline-dot" />
            <div>
              <div className="timeline-line">
                <strong>{event.event_type}</strong>
                <time>{formatDate(event.timestamp)}</time>
              </div>
              <p>{event.message}</p>
            </div>
          </div>
        ))
      ) : (
        <div className="empty-state">Timeline events are unavailable.</div>
      )}
    </div>
  );
}

export function ContextGraph({ graph }: { graph?: Graph }) {
  const [focus, setFocus] = useState<string | null>(null);
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  return (
    <div className="graph-shell">
      <div className="graph-toolbar">
        <span>
          <GitBranch size={15} /> {nodes.length} entities · {edges.length} relationships
        </span>
        <span className="graph-hint">
          <MousePointer2 size={13} /> Select an entity to inspect
        </span>
      </div>
      {nodes.length ? (
        <div className="graph-canvas">
          {nodes.map((node, index) => (
            <button
              key={node.id}
              className={`graph-node graph-${node.type} ${focus === node.id ? "focused" : ""}`}
              onClick={() => setFocus(focus === node.id ? null : node.id)}
            >
              <span className="graph-node-type">{node.type}</span>
              <strong>{node.label}</strong>
            </button>
          ))}
          <div className="graph-relationships">
            {edges.map((edge, index) => (
              <span key={`${edge.join("-")}-${index}`}>
                <b>{edge[0]}</b>
                <ChevronRight size={12} />
                <b>{edge[1]}</b>
              </span>
            ))}
          </div>
        </div>
      ) : (
        <div className="empty-state">No contextual relationships discovered.</div>
      )}
    </div>
  );
}

export function TrustProfileVisualizer({ profile }: { profile?: ReportData["digital_trust_profile"] }) {
  if (!profile) return null;

  const dimensions = [
    { label: "Identity Trust", score: profile.identity_trust, desc: "Domain legitimacy & SSL subject alignment" },
    { label: "Security Trust", score: profile.security_trust, desc: "HTTPS, standard ports & DNS health" },
    { label: "Content Trust", score: profile.content_trust, desc: "Language coherence & lack of urgency spam" },
    { label: "Interaction Trust", score: profile.interaction_trust, desc: "Form destinations & credential safety" },
    { label: "Privacy Trust", score: profile.privacy_trust, desc: "Proportionality of requested user data" },
    { label: "Behavioral Trust", score: profile.behavioral_trust, desc: "Clean navigation & absence of forced downloads" },
    { label: "Authenticity", score: profile.authenticity, desc: "Multi-factor composite authenticity" },
  ];

  return (
    <div className="trust-profile-box">
      <div className="trust-dims-grid">
        {dimensions.map((dim) => {
          const colorClass =
            dim.score >= 75 ? "score-high" : dim.score >= 50 ? "score-mid" : "score-low";
          return (
            <div className="trust-dim-card" key={dim.label}>
              <div className="trust-dim-top">
                <span className="trust-dim-label">{dim.label}</span>
                <b className={`trust-dim-num ${colorClass}`}>{dim.score}</b>
              </div>
              <div className="trust-dim-bar">
                <div
                  className={`trust-dim-fill ${colorClass}`}
                  style={{ width: `${Math.max(6, dim.score)}%` }}
                />
              </div>
              <p className="trust-dim-desc">{dim.desc}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function IdentityMismatchCard({
  identity,
  safeRoute,
}: {
  identity?: ReportData["identity_analysis"];
  safeRoute?: string | null;
}) {
  if (!identity) return null;
  const isMatch = identity.identity_consistency === "HIGH";

  return (
    <div className={`identity-mismatch-panel ${isMatch ? "match-high" : "match-low"}`}>
      <div className="identity-panel-head">
        <div className="eyebrow">
          <UserCheck size={14} /> Who am I giving this to?
        </div>
        <span className={`consistency-badge ${identity.identity_consistency.toLowerCase()}`}>
          {identity.identity_consistency} CONSISTENCY
        </span>
      </div>

      <div className="identity-comparison-grid">
        <div className="identity-col">
          <span className="col-label">Claimed Service</span>
          <h3 className="col-val">{identity.claimed_service}</h3>
          <small>Presented branding & claims</small>
        </div>
        <div className="identity-col">
          <span className="col-label">Current Website</span>
          <code className="col-val-code">{identity.current_website}</code>
          <small>Address in your browser</small>
        </div>
        <div className="identity-col">
          <span className="col-label">Credential Destination</span>
          <code className="col-val-code">{identity.credential_destination}</code>
          <small>Where submitted data arrives</small>
        </div>
      </div>

      <p className="identity-explanation">{identity.explanation}</p>

      {safeRoute && (
        <div className="safe-route-callout">
          <div>
            <strong>Safer way to continue:</strong>
            <p>Access the genuine service through its verified official portal.</p>
          </div>
          <a
            className="safe-route-btn"
            href={safeRoute}
            target="_blank"
            rel="noopener noreferrer"
          >
            Open Official Site <ArrowUpRight size={15} />
          </a>
        </div>
      )}
    </div>
  );
}

export function PrivacyCheckCard({ privacy }: { privacy?: ReportData["privacy_assessment"] }) {
  if (!privacy) return null;

  return (
    <div className="surface privacy-panel">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">Data Collection Review</span>
          <h2>Privacy Check</h2>
        </div>
        <span className={`risk-pill ${privacy.risk_level.toLowerCase()}`}>
          {privacy.risk_level} COLLECTION
        </span>
      </div>
      <p className="subtle" style={{ margin: "6px 0 16px" }}>
        {privacy.summary}
      </p>
      <div className="privacy-field-grid">
        {privacy.requested_fields.map((field) => (
          <div
            key={field.name}
            className={`privacy-field-pill ${field.detected ? (field.is_sensitive ? "detected-sensitive" : "detected-normal") : "not-detected"}`}
          >
            <span className="field-icon">
              {field.detected ? (field.is_sensitive ? "⚠️" : "✓") : "○"}
            </span>
            <span className="field-name">{field.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function SyntheticWebCard({ synthetic }: { synthetic?: ReportData["synthetic_web_analysis"] }) {
  if (!synthetic || !synthetic.is_synthetic_likely) return null;

  return (
    <div className="surface synthetic-panel">
      <div className="synthetic-head">
        <Bot size={18} className="synthetic-icon" />
        <div>
          <h3>Possible AI-Assisted / Templated Web Content</h3>
          <p className="synthetic-sub">
            Confidence: {Math.round(synthetic.confidence * 100)}% · Contextual indicator
          </p>
        </div>
      </div>
      <p className="synthetic-desc">{synthetic.explanation}</p>
      <div className="synthetic-indicators">
        {synthetic.indicators.map((ind, i) => (
          <span className="synthetic-pill" key={i}>
            • {ind}
          </span>
        ))}
      </div>
      <div className="synthetic-disclaimer">
        ℹ️ <i>{synthetic.context_note}</i>
      </div>
    </div>
  );
}

export function ReportWorkspace({ report }: { report: ReportData }) {
  const [activeTab, setActiveTab] = useState<"overview" | "forensics">("overview");
  const trustProfile = report.digital_trust_profile;
  const trustState = trustProfile?.trust_state || "TRUSTED";
  const overallTrust = trustProfile?.overall_trust ?? Math.max(10, 100 - report.risk_score);

  return (
    <div className="report-workspace-root">
      {/* Top Header */}
      <section className="report-header">
        <div>
          <div className="eyebrow">
            <Layers3 size={13} /> Digital Trust Assessment · {report.id.slice(0, 8)}
          </div>
          <h1>{report.hostname}</h1>
          <p className="report-url">{report.url}</p>
        </div>
        <div className="report-status">
          <TrustBadge state={trustState} />
          <span>
            <Clock3 size={13} /> {formatDate(report.completed_at || report.created_at)}
          </span>
        </div>
      </section>

      {/* Signature "Trust Before You Act" Intervention Banner (if STOP or HIGH_RISK) */}
      {trustState === "STOP" && (
        <section className="intervention-banner banner-stop">
          <div className="banner-icon-col">
            <ShieldX size={28} />
          </div>
          <div className="banner-body">
            <span className="banner-kicker">🔴 STOP BEFORE YOU PROCEED</span>
            <h2>{report.what_happened || report.summary}</h2>
            <p className="banner-why">{report.why_it_matters}</p>
            <div className="banner-advice">
              <strong>Recommendation:</strong> {report.what_to_do || report.recommendation}
            </div>
            {report.safe_route && (
              <div className="banner-actions">
                <a className="btn-primary" href={report.safe_route} target="_blank" rel="noopener noreferrer">
                  Open Verified Official Site <ArrowUpRight size={14} />
                </a>
              </div>
            )}
          </div>
        </section>
      )}

      {trustState === "HIGH_RISK" && (
        <section className="intervention-banner banner-caution">
          <div className="banner-icon-col">
            <ShieldAlert size={26} />
          </div>
          <div className="banner-body">
            <span className="banner-kicker">⚠️ CAUTION: TRUST ADVISORY</span>
            <h2>{report.what_happened || report.summary}</h2>
            <p className="banner-why">{report.why_it_matters}</p>
            <div className="banner-advice">
              <strong>Recommendation:</strong> {report.what_to_do || report.recommendation}
            </div>
          </div>
        </section>
      )}

      {/* Main Score Hero Card */}
      <section className={`trust-hero-card ${riskTone(trustState)}`}>
        <div className="trust-hero-score">
          <span className="hero-kicker">Digital Trust Score</span>
          <div className="score-number-row">
            <strong>{overallTrust}</strong>
            <span>/100</span>
          </div>
          <p className="score-desc">
            Status: <b>{trustState.replace("_", " ")}</b> · {report.evidence.length} auditable signals
          </p>
        </div>
        <div className="trust-hero-summary">
          <span className="hero-kicker">System Verdict</span>
          <h2>{report.summary}</h2>
          <p className="hero-reason">{trustProfile?.state_reason || report.recommendation}</p>
          <div className="hero-metrics-pill-row">
            <span>Calibrated P(phishing): <b>{report.ml_prediction ? `${Math.round(report.ml_prediction.calibrated_probability * 100)}%` : "N/A"}</b></span>
            <span>Authenticity: <b>{report.website_authenticity?.level || "Evaluated"}</b></span>
            <span>Identity: <b>{report.identity_analysis?.identity_consistency || "Unknown"}</b></span>
          </div>
        </div>
      </section>

      {/* Navigation Tabs */}
      <div className="workspace-tabs" role="tablist">
        <button
          className={activeTab === "overview" ? "active" : ""}
          onClick={() => setActiveTab("overview")}
          role="tab"
        >
          Digital Trust Story
        </button>
        <button
          className={activeTab === "forensics" ? "active" : ""}
          onClick={() => setActiveTab("forensics")}
          role="tab"
        >
          Technical Forensics & Model Details
        </button>
      </div>

      {activeTab === "overview" ? (
        <div className="story-layout">
          {/* 1. Who am I giving this to? */}
          <IdentityMismatchCard
            identity={report.identity_analysis}
            safeRoute={report.safe_route}
          />

          {/* 2. Digital Trust Profile (7 Dimensions) */}
          <section className="surface section-block">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">Multidimensional Assessment</span>
                <h2>Digital Trust Profile</h2>
              </div>
              <span className="panel-count">7 Dimensions</span>
            </div>
            <TrustProfileVisualizer profile={report.digital_trust_profile} />
          </section>

          {/* 3. Synthetic Web & Privacy Check Grid */}
          <div className="twin-grid">
            <PrivacyCheckCard privacy={report.privacy_assessment} />
            <div className="twin-col">
              <SyntheticWebCard synthetic={report.synthetic_web_analysis} />
              {report.campaign_similarity?.has_related_campaign && (
                <div className="surface campaign-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="section-kicker">Cross-Investigation Analysis</span>
                      <h2>Campaign Relationships</h2>
                    </div>
                  </div>
                  <p className="campaign-note">
                    {report.campaign_similarity.potential_relationship_note}
                  </p>
                  <div className="campaign-tags">
                    {report.campaign_similarity.shared_characteristics.map((sc, i) => (
                      <span className="campaign-tag" key={i}>
                        {sc}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* 4. Structured Human Explanation */}
          <section className="explanation-block">
            <div className="explanation-head">
              <span className="section-kicker">Transparent Decision Guidance</span>
              <h2>Detect · Understand · Protect · Guide</h2>
            </div>
            <div className="explanation-columns">
              <div className="exp-col">
                <span className="label observed">What happened?</span>
                <p>{report.what_happened || report.summary}</p>
              </div>
              <div className="exp-col">
                <span className="label inferred">Why does it matter?</span>
                <p>{report.why_it_matters || "Entering sensitive credentials without verified authenticity presents severe security risks."}</p>
              </div>
              <div className="exp-col">
                <span className="label recommended">What should I do?</span>
                <p>{report.what_to_do || report.recommendation}</p>
              </div>
            </div>
          </section>

          {/* 5. Evidence & Timeline */}
          <div className="lower-grid">
            <section className="surface">
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">Evidence Layer</span>
                  <h2>Observed Evidence</h2>
                </div>
                <span className="panel-count">{report.evidence.length} signals</span>
              </div>
              <EvidenceList items={report.evidence} />
            </section>
            <section className="surface">
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">Incident Timeline</span>
                  <h2>Event Stream</h2>
                </div>
              </div>
              <Timeline events={report.events} />
            </section>
          </div>
        </div>
      ) : (
        /* Technical Forensics Section */
        <div className="forensics-layout">
          {/* Calibrated ML Inference Details */}
          <section className="surface forensics-card">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">Supervised ML Layer</span>
                <h2>Calibrated XGBoost Model Output</h2>
              </div>
              <span className="panel-count">
                {report.ml_prediction?.model_name || "Calibrated XGBoost"}
              </span>
            </div>
            <div className="ml-metrics-grid">
              <div className="ml-metric">
                <span>P(Phishing) Probability</span>
                <b>{report.ml_prediction ? `${(report.ml_prediction.calibrated_probability * 100).toFixed(1)}%` : "N/A"}</b>
              </div>
              <div className="ml-metric">
                <span>Calibration Method</span>
                <b>{report.ml_prediction?.calibration_method || "Platt Scaling (Sigmoid)"}</b>
              </div>
              <div className="ml-metric">
                <span>Model Version</span>
                <b>{report.ml_prediction?.model_version || "1.0.0"}</b>
              </div>
              <div className="ml-metric">
                <span>Binary Decision</span>
                <b>{report.ml_prediction?.is_phishing ? "FLAGGED PHISHING" : "BENIGN"}</b>
              </div>
            </div>

            {report.ml_prediction?.feature_contributions && (
              <div className="ml-contributions">
                <span className="subtle-kicker">Feature Group Contributions</span>
                <div className="contrib-row">
                  {Object.entries(report.ml_prediction.feature_contributions).map(([grp, val]) => (
                    <div key={grp} className="contrib-item">
                      <span>{grp}</span>
                      <b>{val}</b>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>

          {/* Context Relationship Graph */}
          <section className="surface forensics-card">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">Context Graph</span>
                <h2>Entity Relationships</h2>
              </div>
            </div>
            <ContextGraph graph={report.context_graph} />
          </section>

          {/* Raw Observations and Feature Vector */}
          <div className="twin-grid">
            <section className="surface">
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">Webpage Structure</span>
                  <h2>Observed DOM Attributes</h2>
                </div>
              </div>
              <dl className="data-list">
                {Object.entries(report.page_analysis || {})
                  .filter(([, v]) => v !== null && v !== undefined)
                  .map(([k, v]) => (
                    <div key={k}>
                      <dt>{k.replaceAll("_", " ")}</dt>
                      <dd>{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
                    </div>
                  ))}
              </dl>
            </section>

            <section className="surface">
              <div className="panel-heading">
                <div>
                  <span className="section-kicker">URL Feature Vector</span>
                  <h2>Deterministic Input Features</h2>
                </div>
              </div>
              <dl className="data-list">
                {Object.entries(report.features || {}).map(([k, v]) => (
                  <div key={k}>
                    <dt>{k.replaceAll("_", " ")}</dt>
                    <dd>{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
                  </div>
                ))}
              </dl>
            </section>
          </div>
        </div>
      )}
    </div>
  );
}
