import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { fetchDiff, fetchReports, updateTriage, DiffDetail, Reports } from "./api";

interface DiffDetailViewProps {
  apiBase: string;
}

export default function DiffDetailView({ apiBase }: DiffDetailViewProps) {
  const { diffId } = useParams<{ diffId: string }>();
  const [diff, setDiff] = useState<DiffDetail | null>(null);
  const [reports, setReports] = useState<Reports | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [triageState, setTriageState] = useState("");
  const [triageNotes, setTriageNotes] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!diffId) return;
    let cancelled = false;
    Promise.all([fetchDiff(apiBase, diffId), fetchReports(apiBase, diffId)])
      .then(([d, r]) => {
        if (!cancelled) {
          setDiff(d);
          setReports(r);
          setTriageState(d.state);
          setTriageNotes(d.notes || "");
        }
      })
      .catch((e) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [apiBase, diffId]);

  const handleSaveTriage = () => {
    if (!diffId || !triageState) return;
    setSaving(true);
    updateTriage(apiBase, diffId, triageState, triageNotes)
      .then(() => setSaving(false))
      .catch(() => setSaving(false));
  };

  if (loading) return <p>Loading…</p>;
  if (error) return <p className="error">Error: {error}</p>;
  if (!diff) return <p>Diff not found.</p>;

  const bundle = diff.evidence_bundle;
  const score = diff.score_result;

  return (
    <>
      <h2>Diff {diff.id}</h2>
      <div className="card">
        <p><strong>{diff.build_from}</strong> → <strong>{diff.build_to}</strong> · {diff.component}</p>
        {score && <p className="score">Score: {score.total_score}</p>}
      </div>

      <div className="card">
        <h3>Triage</h3>
        <div className="filter-bar">
          <label>State</label>
          <select value={triageState} onChange={(e) => setTriageState(e.target.value)}>
            <option value="pending">Pending</option>
            <option value="accepted">Accepted</option>
            <option value="denied">Denied</option>
            <option value="in_progress">In progress</option>
          </select>
          <label>Notes</label>
          <input
            value={triageNotes}
            onChange={(e) => setTriageNotes(e.target.value)}
            placeholder="Notes"
            style={{ flex: 1, minWidth: 200 }}
          />
          <button className="btn" onClick={handleSaveTriage} disabled={saving}>Save</button>
        </div>
      </div>

      <div className="card">
        <h3>Evidence bundle</h3>
        {bundle.diff_hunks?.length > 0 && (
          <>
            <h4>Diff hunks</h4>
            {bundle.diff_hunks.map((h) => (
              <pre key={h.hunk_id}>{h.file_path} L{h.old_start}+{h.old_count}\n{h.lines.join("\n")}</pre>
            ))}
          </>
        )}
        {score && score.reasons?.length > 0 && (
          <>
            <h4>Reasons (evidence_refs)</h4>
            <ul>
              {score.reasons.map((r, i) => (
                <li key={i}>{r.reason} — refs: {r.evidence_refs.map((e) => e.stable_id).join(", ")}</li>
              ))}
            </ul>
          </>
        )}
      </div>

      {reports && (
        <>
          {reports.triage && (
            <div className="card">
              <h3>Triage report</h3>
              <p>{reports.triage.summary}</p>
              <p>{reports.triage.score_explanation}</p>
            </div>
          )}
          {reports.vuln_hypotheses?.hypotheses?.length > 0 && (
            <div className="card">
              <h3>Vuln hypotheses</h3>
              <ul>
                {reports.vuln_hypotheses.hypotheses.map((h, i) => (
                  <li key={i}>{h.statement} — {h.test_approach}</li>
                ))}
              </ul>
            </div>
          )}
          {reports.fuzz_plan && (
            <div className="card">
              <h3>Fuzz plan</h3>
              <p><strong>Target:</strong> {reports.fuzz_plan.target_surface}</p>
              <p><strong>Harness:</strong> {reports.fuzz_plan.harness_sketch}</p>
              <p><strong>Seeds:</strong> {reports.fuzz_plan.seed_strategy}</p>
              <ul>
                {reports.fuzz_plan.success_metrics?.map((m, i) => <li key={i}>{m}</li>)}
              </ul>
            </div>
          )}
          {reports.telemetry?.recommendations?.length > 0 && (
            <div className="card">
              <h3>Telemetry recommendations</h3>
              <ul>
                {reports.telemetry.recommendations.map((r, i) => (
                  <li key={i}>{r.recommendation} — {r.correlation}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </>
  );
}
