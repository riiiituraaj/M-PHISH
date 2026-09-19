import {
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";

export function riskTone(classification: string) {
  const value = (classification || "").toUpperCase();
  if (value === "STOP" || value === "CRITICAL") return "stop";
  if (value === "HIGH" || value === "HIGH_RISK") return "high";
  if (value === "MEDIUM" || value === "MODERATE" || value === "CAUTION") return "moderate";
  if (value === "LOW" || value === "TRUSTED") return "low";
  return "unknown";
}

export function RiskBadge({ classification }: { classification: string }) {
  const tone = riskTone(classification);
  const Icon =
    tone === "low"
      ? CheckCircle2
      : tone === "moderate"
        ? AlertTriangle
        : tone === "high"
          ? ShieldAlert
          : tone === "stop"
            ? ShieldX
            : HelpCircle;

  const displayLabel = classification.replace("_", " ");

  return (
    <span className={`risk-badge ${tone}`}>
      <Icon size={14} />
      {displayLabel}
    </span>
  );
}

export function TrustBadge({ state }: { state: string }) {
  const norm = (state || "TRUSTED").toUpperCase();
  const Icon =
    norm === "TRUSTED"
      ? ShieldCheck
      : norm === "CAUTION"
        ? AlertTriangle
        : norm === "HIGH_RISK"
          ? ShieldAlert
          : ShieldX;

  const tone =
    norm === "TRUSTED"
      ? "low"
      : norm === "CAUTION"
        ? "moderate"
        : norm === "HIGH_RISK"
          ? "high"
          : "stop";

  return (
    <span className={`risk-badge ${tone}`}>
      <Icon size={14} />
      {norm.replace("_", " ")}
    </span>
  );
}

export function RiskScore({
  score,
  classification,
}: {
  score: number;
  classification: string;
}) {
  return (
    <div className={`risk-score ${riskTone(classification)}`}>
      <div>
        <strong>{score}</strong>
        <span>/100</span>
      </div>
      <RiskBadge classification={classification} />
    </div>
  );
}
