const defaultBase = "/api";

export interface QueueItem {
  id: string;
  diff_id: string;
  build_from: string;
  build_to: string;
  component: string;
  score: number;
  state: string;
  notes: string;
  created_at: string | null;
}

export interface EvidenceRef {
  ref_type: string;
  artifact_id: string | null;
  stable_id: string;
}

export interface Reason {
  reason: string;
  score_contribution: number;
  evidence_refs: EvidenceRef[];
}

export interface ScoreResult {
  total_score: number;
  reasons: Reason[];
  diff_id: string;
}

export interface DiffHunk {
  file_path: string;
  old_start: number;
  old_count: number;
  new_start: number;
  new_count: number;
  lines: string[];
  hunk_id: string;
}

export interface EvidenceBundle {
  diff_hunks: DiffHunk[];
  source_features: unknown[];
  binary_features_from: unknown[];
  binary_features_to: unknown[];
  binary_diff_pairs: unknown[];
  log_templates: unknown[];
  log_to_binary_matches: [string, string][];
}

export interface DiffDetail {
  id: string;
  build_from: string;
  build_to: string;
  component: string;
  evidence_bundle: EvidenceBundle;
  score_result: ScoreResult | null;
  state: string;
  notes: string;
}

export interface Reports {
  triage?: { summary: string; score_explanation: string; citations: EvidenceRef[] };
  reverse_context?: { anchor_strings: string[]; probable_entry_points: string[]; oss_context_snippets: unknown[] };
  vuln_hypotheses?: { hypotheses: { statement: string; evidence_refs: EvidenceRef[]; test_approach: string }[] };
  fuzz_plan?: { target_surface: string; harness_sketch: string; seed_strategy: string; success_metrics: string[] };
  telemetry?: { recommendations: { recommendation: string; subsystem_category: string; correlation: string }[] };
}

function apiUrl(apiBase: string, path: string): string {
  const full = apiBase.replace(/\/$/, "") + path;
  if (full.startsWith("http")) return full;
  return `${window.location.origin}${full.startsWith("/") ? full : "/" + full}`;
}

export async function fetchQueue(
  apiBase: string,
  params: { component?: string; state?: string; min_score?: number; build_from?: string; build_to?: string } = {}
): Promise<QueueItem[]> {
  const url = new URL(apiUrl(apiBase, "/queue"));
  Object.entries(params).forEach(([k, v]) => {
    if (v != null && v !== "") url.searchParams.set(k, String(v));
  });
  const r = await fetch(url.toString());
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

export async function fetchDiff(apiBase: string, diffId: string): Promise<DiffDetail> {
  const r = await fetch(apiUrl(apiBase, `/diff/${diffId}`));
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

export async function fetchReports(apiBase: string, diffId: string): Promise<Reports> {
  const r = await fetch(apiUrl(apiBase, `/reports/${diffId}`));
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

export async function updateTriage(
  apiBase: string,
  diffId: string,
  state: string,
  notes: string
): Promise<void> {
  const r = await fetch(apiUrl(apiBase, `/diff/${diffId}/triage`), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ state, notes }),
  });
  if (!r.ok) throw new Error(r.statusText);
}
