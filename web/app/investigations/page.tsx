"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Search, SlidersHorizontal } from "lucide-react";
import { listInvestigations, Report } from "../../lib/api";
import { RiskBadge } from "../../components/risk";

export default function Investigations() {
  const [reports, setReports] = useState<Report[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [error, setError] = useState("");
  useEffect(() => {
    listInvestigations()
      .then(setReports)
      .catch((e) =>
        setError(e instanceof Error ? e.message : "History is unavailable."),
      );
  }, []);
  const visible = useMemo(
    () =>
      reports.filter(
        (report) =>
          (filter === "ALL" || report.classification === filter) &&
          `${report.hostname} ${report.url}`
            .toLowerCase()
            .includes(query.toLowerCase()),
      ),
    [reports, query, filter],
  );
  return (
    <main className="investigations-page">
      <div className="section-head">
        <div>
          <div className="eyebrow">
            <SlidersHorizontal size={13} /> Intelligence workspace
          </div>
          <h1>Investigations</h1>
          <p className="subtle">
            A traceable record of every website reviewed by the engine.
          </p>
        </div>
      </div>
      <div className="list-tools">
        <label>
          <Search size={15} />
          <input
            aria-label="Search investigations"
            placeholder="Search target or URL"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <select
          aria-label="Filter classification"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        >
          <option value="ALL">All classifications</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>
      <div className="surface recent">
        {error ? (
          <div className="empty" role="alert">
            {error}
          </div>
        ) : visible.length ? (
          visible.map((report) => (
            <Link
              className="recent-row"
              href={`/investigations/${report.id}`}
              key={report.id}
            >
              <div>
                <div className="url">{report.hostname}</div>
                <div className="date">
                  {report.url} ·{" "}
                  {report.created_at
                    ? new Date(report.created_at).toLocaleString()
                    : "Completed"}
                </div>
              </div>
              <div className="row-summary">
                <span>{report.evidence.length} evidence</span>
                <RiskBadge classification={report.classification} />
                <b>{report.risk_score}</b>
              </div>
            </Link>
          ))
        ) : (
          <div className="empty">
            {reports.length
              ? "No investigations match these filters."
              : "No investigations yet. Start from the dashboard."}
          </div>
        )}
      </div>
    </main>
  );
}
