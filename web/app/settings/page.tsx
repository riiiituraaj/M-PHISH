"use client";
import { useState } from "react";
import { GraduationCap, Lock, Settings2, Shield, ShieldCheck, SlidersHorizontal } from "lucide-react";

export default function Settings() {
  const [mode, setMode] = useState("standard");
  const [level, setLevel] = useState("standard");
  const [saved, setSaved] = useState(false);

  const protectionModes = [
    {
      id: "standard",
      title: "Standard Protection",
      description: "Balanced everyday protection. Alerts only when strong inconsistency or harvesting signals appear.",
      icon: Shield,
    },
    {
      id: "high",
      title: "High Protection",
      description: "Heightened vigilance. Activates 'Trust Before You Act' warnings around any unfamiliar login or form interaction.",
      icon: Lock,
    },
    {
      id: "student",
      title: "Student Mode",
      description: "Specialized for university portals, national scholarship schemes, internship applications, and student loan portals.",
      icon: GraduationCap,
    },
    {
      id: "custom",
      title: "Custom Policy",
      description: "Configurable alert thresholds for security researchers and cybersecurity evaluators.",
      icon: SlidersHorizontal,
    },
  ];

  function handleSave() {
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  }

  return (
    <main className="settings-page">
      <div className="section-head">
        <div>
          <div className="eyebrow">
            <Settings2 size={13} /> Protection Configuration
          </div>
          <h1>Platform Settings</h1>
          <p className="subtle">
            Configure protection posture and explanation depth for your browsing environment.
          </p>
        </div>
      </div>

      <div className="settings-grid">
        {/* Protection Modes */}
        <section className="surface setting-card">
          <div className="section-kicker">
            <Shield size={14} /> Active Protection Mode
          </div>
          <h2>Select Protection Profile</h2>
          <p className="subtle" style={{ margin: "4px 0 16px" }}>
            Tailors sensitivity to your interaction context without compromising security baselines.
          </p>

          <div className="mode-options-list">
            {protectionModes.map((p) => {
              const Icon = p.icon;
              const isSelected = mode === p.id;
              return (
                <label
                  className={`mode-card ${isSelected ? "mode-selected" : ""}`}
                  key={p.id}
                  onClick={() => setMode(p.id)}
                >
                  <input
                    type="radio"
                    name="protection_mode"
                    checked={isSelected}
                    onChange={() => setMode(p.id)}
                  />
                  <div className="mode-content">
                    <div className="mode-title-row">
                      <Icon size={16} />
                      <strong>{p.title}</strong>
                    </div>
                    <p>{p.description}</p>
                  </div>
                </label>
              );
            })}
          </div>
        </section>

        {/* Explanation Level & Boundaries */}
        <div className="settings-col">
          <section className="surface setting-card">
            <div className="section-kicker">
              <SlidersHorizontal size={13} /> Explanation Layer
            </div>
            <h2>Guidance Presentation Level</h2>
            <p className="subtle" style={{ margin: "4px 0 14px" }}>
              Controls how forensic evidence is phrased in the UI.
            </p>
            {["simple", "standard", "technical"].map((x) => (
              <label className="choice" key={x}>
                <input
                  type="radio"
                  name="explanation_level"
                  checked={level === x}
                  onChange={() => setLevel(x)}
                />
                <span>
                  <b style={{ textTransform: "capitalize" }}>{x}</b>
                  <br />
                  <span className="subtle">
                    {x === "simple"
                      ? "Direct, clear guidance for normal users (Detect → Protect → Guide)."
                      : x === "standard"
                        ? "Balanced evidence, confidence ratings, and trust dimensions."
                        : "Deep technical forensics, calibrated ML probabilities, and raw feature vectors."}
                  </span>
                </span>
              </label>
            ))}

            <button className="save-btn" onClick={handleSave} style={{ marginTop: "18px" }}>
              {saved ? "Settings Saved ✓" : "Save Preferences"}
            </button>
          </section>

          <section className="surface setting-card">
            <div className="section-kicker">
              <ShieldCheck size={13} /> Enforcement Posture
            </div>
            <h2>Active Security Controls</h2>
            <div className="security-boundary-list">
              <p><span className="status-dot green" /> Calibrated XGBoost & Platt scaling active</p>
              <p><span className="status-dot green" /> SSRF & private IP targets strictly rejected</p>
              <p><span className="status-dot green" /> Zero automated credential submission guarantee</p>
              <p><span className="status-dot green" /> Deterministic evidence fusion authoritative</p>
              <p><span className="status-dot green" /> AI phrasing grounded in structured facts</p>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
