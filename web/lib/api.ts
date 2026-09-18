export type Evidence = {
  id: string;
  category: string;
  title: string;
  description: string;
  confidence: number;
  severity: string;
  weight: number;
  source?: string;
  created_at?: string;
};

export type GraphNode = { id: string; type: string; label: string };
export type Graph = {
  nodes: GraphNode[];
  edges: string[][];
  context?: Record<string, unknown>;
};

export type Event = { event_type: string; message: string; timestamp: string };

export type DigitalTrustProfile = {
  identity_trust: number;
  security_trust: number;
  content_trust: number;
  interaction_trust: number;
  privacy_trust: number;
  behavioral_trust: number;
  authenticity: number;
  overall_trust: number;
  trust_state: "TRUSTED" | "CAUTION" | "HIGH_RISK" | "STOP";
  state_reason: string;
};

export type WebsiteAuthenticity = {
  identity_score: number;
  content_score: number;
  behavior_score: number;
  consistency_score: number;
  overall_score: number;
  level: string;
  explanation: string;
};

export type IdentityAnalysis = {
  claimed_service: string;
  current_website: string;
  credential_destination: string;
  identity_consistency: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  explanation: string;
  safe_route: string | null;
  is_impersonation_suspected: boolean;
};

export type RequestedField = {
  name: string;
  label: string;
  is_sensitive: boolean;
  detected: boolean;
};

export type PrivacyAssessment = {
  privacy_risk_score: number;
  risk_level: string;
  requested_fields: RequestedField[];
  sensitive_count: number;
  total_count: number;
  summary: string;
};

export type SyntheticWebAnalysis = {
  is_synthetic_likely: boolean;
  confidence: number;
  indicators: string[];
  explanation: string;
  context_note: string;
};

export type DeceptiveClaimAnalysis = {
  claimed_category: string;
  asserted_claim: string;
  observed_characteristics: string;
  claim_consistency: string;
  explanation: string;
};

export type DownloadSafetyAssessment = {
  has_download: boolean;
  file_name: string | null;
  file_extension: string | null;
  is_executable_or_script: boolean;
  risk_level: string;
  explanation: string;
};

export type CampaignSimilarity = {
  has_related_campaign: boolean;
  confidence: number;
  shared_characteristics: string[];
  potential_relationship_note: string;
  related_targets: string[];
};

export type MLPrediction = {
  risk: number;
  calibrated_probability: number;
  raw_probability: number;
  model_name: string;
  model_version: string;
  feature_version: string;
  calibration_method: string;
  feature_contributions: Record<string, number>;
  is_phishing: boolean;
};

export type TrustBeforeYouAct = {
  requires_intervention: boolean;
  banner_title: string;
  banner_message: string;
  recommended_action: string;
  safe_route: string | null;
  actions: string[];
};

export type Report = {
  id: string;
  url: string;
  hostname: string;
  risk_score: number;
  classification: string;
  confidence: number;
  top_factors: string[];
  summary: string;
  recommendation: string;
  what_happened?: string;
  why_it_matters?: string;
  what_to_do?: string;
  evidence: Evidence[];
  events: Event[];
  features: Record<string, unknown>;
  page_analysis: Record<string, any>;
  domain_analysis?: Record<string, any>;
  context_graph?: Graph;
  context?: Record<string, unknown>;
  created_at?: string;
  completed_at?: string;
  ai_report?: {
    provider: string;
    model?: string;
    uncertainty?: string;
    summary?: string;
    recommended_action?: string;
    what_happened?: string;
    why_it_matters?: string;
    what_to_do?: string;
  };
  digital_trust_profile?: DigitalTrustProfile;
  website_authenticity?: WebsiteAuthenticity;
  identity_analysis?: IdentityAnalysis;
  privacy_assessment?: PrivacyAssessment;
  synthetic_web_analysis?: SyntheticWebAnalysis;
  deceptive_claim_analysis?: DeceptiveClaimAnalysis;
  download_safety?: DownloadSafetyAssessment;
  campaign_similarity?: CampaignSimilarity;
  ml_prediction?: MLPrediction;
  safe_route?: string | null;
  trust_before_you_act?: TrustBeforeYouAct;
};

export type ResearchExperiment = {
  experiment_id: string;
  name: string;
  feature_groups: string[];
  num_features: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number;
  pr_auc: number;
  false_positive_rate: number;
  false_negative_rate: number;
  brier_score: number;
  inference_latency_ms: number;
  hypothesis_confirmed: string;
};

export type ResearchSuite = {
  research_question: string;
  experiments: ResearchExperiment[];
  primary_model: string;
  benchmark_dataset_samples: number;
  evaluated_at: string;
};

export type DemoScenario = {
  id: string;
  title: string;
  url: string;
  expected_state: string;
  description: string;
  safe_route?: string;
};

const api = () => process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function normalizeUrl(value: string) {
  const trimmed = value.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

type Envelope<T> = {
  success: boolean;
  data: T;
  request_id: string;
  error?: string;
};

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${api()}${path}`, {
      ...options,
      cache: "no-store",
    });
  } catch {
    throw new Error("The analysis service is unreachable.");
  }
  const envelope = (await response
    .json()
    .catch(() => null)) as Envelope<T> | null;
  if (!response.ok || !envelope?.success)
    throw new Error(
      envelope?.error || `API request failed (${response.status})`,
    );
  return envelope.data;
}

export async function investigate(value: string): Promise<Report> {
  const url = normalizeUrl(value);
  const job = await request<{ id: string; status: string }>(
    "/api/v1/investigations",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    },
  );
  for (let attempt = 0; attempt < 40; attempt++) {
    const status = await request<Report & { status: string }>(
      `/api/v1/investigations/${encodeURIComponent(job.id)}`,
    );
    if (status.status === "COMPLETED") return status;
    if (status.status === "FAILED") throw new Error("Investigation failed");
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Investigation timed out");
}

export async function listInvestigations(): Promise<Report[]> {
  return request<Report[]>("/api/v1/investigations");
}

export async function getReport(id: string): Promise<Report> {
  return request<Report>(`/api/v1/investigations/${encodeURIComponent(id)}`);
}

export async function getResearchExperiments(): Promise<ResearchSuite> {
  return request<ResearchSuite>("/api/v1/research/experiments");
}

export async function getDemoScenarios(): Promise<DemoScenario[]> {
  const response = await request<{ success: boolean; data: DemoScenario[] }>("/api/v1/demo/scenarios");
  return response.data;
}
