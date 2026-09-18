"use client";
import { useEffect, useState } from "react";
import {
  Award,
  BarChart3,
  CheckCircle,
  Database,
  FlaskConical,
  Gauge,
  Layers,
  ShieldCheck,
  Sparkles,
  TrendingUp,
} from "lucide-react";
import { getResearchExperiments, ResearchSuite } from "../../lib/api";

export default function ResearchPage() {
  const [suite, setSuite] = useState<ResearchSuite | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getResearchExperiments()
      .then((data) => {
        setSuite(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Failed to load experiment data");
        setLoading(false);
      });
  }, []);

  return (
    <main className="research-page">
      <div className="section-head">
        <div>
          <div className="eyebrow">
            <FlaskConical size={14} /> Empirical Cybersecurity Research
          </div>
          <h1>Multimodal Ablation Study</h1>
          <p className="subtle">
            Experimental evaluation quantifying the additive predictive value of multimodal
            evidence layers over conventional URL-only classifiers.
          </p>
        </div>
      </div>

      {/* Core Research Question Banner */}
      <section className="research-hypothesis-card">
        <div className="hypothesis-icon">
          <Sparkles size={22} />
        </div>
        <div>
          <span className="section-kicker">Primary Research Hypothesis</span>
          <h2>
            &ldquo;Can a multimodal digital trust assessment approach provide more useful and
            interpretable protection against modern web deception than conventional URL-only
            phishing detection?&rdquo;
          </h2>
          <p>
            Evaluated on a balanced benchmark test suite (n = 2,000 samples) across URL, Domain,
            Webpage, Behavioral, and Contextual feature groups using Calibrated XGBoost.
          </p>
        </div>
      </section>

      {loading && (
        <div className="empty" style={{ padding: "40px" }}>
          Running multimodal ablation benchmark across Experiments A to E...
        </div>
      )}

      {error && (
        <div className="empty" role="alert" style={{ color: "#ef4444" }}>
          {error}
        </div>
      )}

      {suite && (
        <>
          {/* Main Experiments Comparison Table */}
          <section className="surface experiment-table-card">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">Benchmark Ablation Matrix</span>
                <h2>Model Performance Across Modality Conditions</h2>
              </div>
              <span className="panel-count">5 Conditions</span>
            </div>

            <div className="table-wrapper">
              <table className="research-table">
                <thead>
                  <tr>
                    <th>Experiment</th>
                    <th>Modalities</th>
                    <th>Features</th>
                    <th>Accuracy</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>F1 Score</th>
                    <th>ROC-AUC</th>
                    <th>FPR</th>
                    <th>Brier Score</th>
                    <th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {suite.experiments.map((exp, index) => {
                    const isWinner = index === suite.experiments.length - 1;
                    return (
                      <tr key={exp.experiment_id} className={isWinner ? "row-winner" : ""}>
                        <td>
                          <strong>{exp.name}</strong>
                          {isWinner && <span className="winner-tag">Optimal</span>}
                        </td>
                        <td>
                          <span className="modalities-pill">
                            {exp.feature_groups.join(" + ")}
                          </span>
                        </td>
                        <td>{exp.num_features}</td>
                        <td>{(exp.accuracy * 100).toFixed(1)}%</td>
                        <td>{(exp.precision * 100).toFixed(1)}%</td>
                        <td>{(exp.recall * 100).toFixed(1)}%</td>
                        <td>
                          <b>{(exp.f1 * 100).toFixed(1)}%</b>
                        </td>
                        <td>{exp.roc_auc.toFixed(3)}</td>
                        <td>{(exp.false_positive_rate * 100).toFixed(1)}%</td>
                        <td>{exp.brier_score.toFixed(3)}</td>
                        <td>{exp.inference_latency_ms} ms</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          {/* Key Findings Grid */}
          <div className="research-findings-grid">
            <div className="surface finding-card">
              <div className="finding-header">
                <TrendingUp size={18} />
                <h3>Recall Elevation via Webpage Inspection</h3>
              </div>
              <p>
                Adding DOM inspection (forms, credential inputs) in <b>Experiment C</b> increases
                detection recall significantly over URL-only baselines, eliminating blind spots
                for legitimate cloud services hosting credential harvesting forms.
              </p>
            </div>

            <div className="surface finding-card">
              <div className="finding-header">
                <ShieldCheck size={18} />
                <h3>FPR Suppression via Domain & Identity</h3>
              </div>
              <p>
                Incorporating DNS A/AAAA records, TLS attributes, and brand alignment in{" "}
                <b>Experiment B & E</b> prevents false positives on complex legitimate portals,
                delivering a balanced, non-alarmist consumer experience.
              </p>
            </div>

            <div className="surface finding-card">
              <div className="finding-header">
                <Gauge size={18} />
                <h3>Superior Calibration & Brier Score</h3>
              </div>
              <p>
                Platt scaling (sigmoid calibration) applied to XGBoost outputs yields a lower Brier
                score across all conditions, ensuring that calculated probabilities accurately
                reflect true empirical risk rather than arbitrary confidence heuristics.
              </p>
            </div>
          </div>
        </>
      )}
    </main>
  );
}

