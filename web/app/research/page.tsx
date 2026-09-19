"use client";
import { useEffect, useState } from "react";
import { BarChart3, FlaskConical, Gauge, ShieldCheck, Sparkles, TrendingUp } from "lucide-react";
import { getResearchExperiments, ResearchSuite } from "../../lib/api";

export default function ResearchPage() {
  const [suite, setSuite] = useState<ResearchSuite | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getResearchExperiments()
      .then(setSuite)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load experiment data"))
      .finally(() => setLoading(false));
  }, []);

  return (
    <main className="research-page">
      <div className="section-head">
        <div>
          <div className="eyebrow"><FlaskConical size={14} /> Empirical Cybersecurity Research</div>
          <h1>Multimodal Ablation Study</h1>
          <p className="subtle">
            A reproducible engineering benchmark for measuring how additional web-safety evidence changes model behaviour.
          </p>
        </div>
      </div>

      <section className="research-hypothesis-card">
        <div className="hypothesis-icon"><Sparkles size={22} /></div>
        <div>
          <span className="section-kicker">Research question</span>
          <h2>
            Can multimodal digital-trust evidence provide more useful and interpretable protection than URL-only analysis?
          </h2>
          <p>
            The bundled experiment evaluates five modality conditions on a balanced synthetic development benchmark
            with an independent held-out test split.
          </p>
        </div>
      </section>

      {loading && <div className="empty" style={{ padding: "40px" }}>Running multimodal ablation benchmark across Experiments A to E...</div>}
      {error && <div className="empty" role="alert" style={{ color: "#ef4444" }}>{error}</div>}

      {suite && (
        <>
          <section className="surface" style={{ padding: 18, marginBottom: 14, border: "1px solid var(--line)" }}>
            <div className="section-kicker">Evaluation provenance</div>
            <p className="subtle" style={{ margin: "8px 0 0", lineHeight: 1.6 }}>
              {suite.dataset_provenance || "Synthetic development benchmark."} Results are intended for regression testing,
              ablation analysis, and reproducibility. They are not real-world phishing prevalence estimates.
            </p>
          </section>

          <section className="surface experiment-table-card">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">Benchmark ablation matrix</span>
                <h2>Performance by evidence layer</h2>
              </div>
              <span className="panel-count">{suite.experiments.length} Conditions</span>
            </div>

            <div className="table-wrapper">
              <table className="research-table">
                <thead>
                  <tr>
                    <th>Experiment</th><th>Modalities</th><th>Features</th><th>Accuracy</th><th>Precision</th>
                    <th>Recall</th><th>F1</th><th>ROC-AUC</th><th>FPR</th><th>Brier</th><th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {suite.experiments.map((exp) => (
                    <tr key={exp.experiment_id}>
                      <td><strong>{exp.name}</strong></td>
                      <td><span className="modalities-pill">{exp.feature_groups.join(" + ")}</span></td>
                      <td>{exp.num_features}</td>
                      <td>{(exp.accuracy * 100).toFixed(1)}%</td>
                      <td>{(exp.precision * 100).toFixed(1)}%</td>
                      <td>{(exp.recall * 100).toFixed(1)}%</td>
                      <td><b>{(exp.f1 * 100).toFixed(1)}%</b></td>
                      <td>{exp.roc_auc.toFixed(3)}</td>
                      <td>{(exp.false_positive_rate * 100).toFixed(1)}%</td>
                      <td>{exp.brier_score.toFixed(3)}</td>
                      <td>{exp.inference_latency_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <div className="research-findings-grid">
            <div className="surface finding-card">
              <div className="finding-header"><TrendingUp size={18} /><h3>Incremental signal coverage</h3></div>
              <p>
                DOM and behavioural features expose signals unavailable to a URL-only classifier. Use the table to
                compare Experiment C and D against Experiment A on the same held-out split.
              </p>
            </div>
            <div className="surface finding-card">
              <div className="finding-header"><ShieldCheck size={18} /><h3>Cross-layer evidence</h3></div>
              <p>
                Domain, identity, and contextual features allow the system to reason about where data is going and what
                identity a page claims, not only what its URL looks like.
              </p>
            </div>
            <div className="surface finding-card">
              <div className="finding-header"><Gauge size={18} /><h3>Calibration diagnostic</h3></div>
              <p>
                Brier score and ROC-AUC are reported alongside classification metrics. The calibration result is valid
                for this development benchmark and should be re-validated on independently sourced real-world data.
              </p>
            </div>
          </div>

          <section className="surface" style={{ marginTop: 14, padding: 18 }}>
            <div className="finding-header"><BarChart3 size={18} /><h3>How to use these results</h3></div>
            <p className="subtle">
              Treat the ablation suite as a regression guard: a code change should not silently degrade recall, false
              positive rate, calibration, or latency. It is deliberately separate from any claim that the detector is
              production-accurate against the live web.
            </p>
          </section>
        </>
      )}
    </main>
  );
}
