import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchQueue, QueueItem } from "./api";

interface QueueViewProps {
  apiBase: string;
}

export default function QueueView({ apiBase }: QueueViewProps) {
  const [items, setItems] = useState<QueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterComponent, setFilterComponent] = useState("");
  const [filterState, setFilterState] = useState("");
  const [filterMinScore, setFilterMinScore] = useState("");

  useEffect(() => {
    let cancelled = false;
    const params: { component?: string; state?: string; min_score?: number } = {};
    if (filterComponent) params.component = filterComponent;
    if (filterState) params.state = filterState;
    const min = parseFloat(filterMinScore);
    if (!isNaN(min)) params.min_score = min;
    fetchQueue(apiBase, params)
      .then((data) => {
        if (!cancelled) setItems(data);
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [apiBase, filterComponent, filterState, filterMinScore]);

  if (loading) return <p>Loading queue…</p>;
  if (error) return <p className="error">Error: {error}</p>;

  return (
    <>
      <h2>Ranked queue</h2>
      <div className="filter-bar">
        <label>Component</label>
        <input
          value={filterComponent}
          onChange={(e) => setFilterComponent(e.target.value)}
          placeholder="e.g. syslogd"
        />
        <label>State</label>
        <select value={filterState} onChange={(e) => setFilterState(e.target.value)}>
          <option value="">Any</option>
          <option value="pending">Pending</option>
          <option value="accepted">Accepted</option>
          <option value="denied">Denied</option>
          <option value="in_progress">In progress</option>
        </select>
        <label>Min score</label>
        <input
          type="number"
          step="0.1"
          value={filterMinScore}
          onChange={(e) => setFilterMinScore(e.target.value)}
          placeholder="0"
        />
      </div>
      <div className="table-wrap card">
        <table>
          <thead>
            <tr>
              <th>Diff</th>
              <th>From → To</th>
              <th>Component</th>
              <th>Score</th>
              <th>State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id}>
                <td>{row.diff_id}</td>
                <td>{row.build_from} → {row.build_to}</td>
                <td>{row.component}</td>
                <td className="score">{row.score}</td>
                <td><span className={`badge ${row.state}`}>{row.state}</span></td>
                <td><Link to={`/diff/${row.diff_id}`}>Detail</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
        {items.length === 0 && <p style={{ padding: "1rem" }}>No items. Run the demo pipeline to populate.</p>}
      </div>
    </>
  );
}
