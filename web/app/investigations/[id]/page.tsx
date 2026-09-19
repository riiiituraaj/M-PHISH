import Link from "next/link";
import { getReport } from "../../../lib/api";
import { ReportWorkspace } from "../../../components/report";

export default async function Report({ params }: { params: { id: string } }) {
  const report = await getReport(params.id);
  return (
    <main className="report">
      <Link className="back" href="/">
        ← Back to overview
      </Link>
      <ReportWorkspace report={report} />
    </main>
  );
}
