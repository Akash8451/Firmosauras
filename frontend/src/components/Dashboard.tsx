import { useState } from "react";
import { RoleSwitcher } from "./RoleSwitcher";
import { UploadPanel } from "./UploadPanel";
import { JobList } from "./JobList";
import { LiveProgress } from "./LiveProgress";
import { ReportViewer } from "./ReportViewer";
import { RagChatPanel } from "./RagChatPanel";
import { ConfigPanel } from "./ConfigPanel";

// The RBAC-aware surface. Each child gates its own controls on the session role
// (reader: view only; analyst: +upload/triage/feedback; admin: +config), so the
// composition here is intentionally simple — capability decisions live next to
// the controls they guard.
export function Dashboard({ wsFactory }: { wsFactory?: (url: string) => WebSocket }) {
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

  return (
    <div className="app">
      <header className="app-header">
        <h1>Firmosaurus</h1>
        <RoleSwitcher />
      </header>

      <main className="grid">
        <div className="col">
          <UploadPanel onUploaded={setSelectedJobId} />
          <JobList selectedJobId={selectedJobId} onSelect={setSelectedJobId} />
          <ConfigPanel />
        </div>
        <div className="col">
          <LiveProgress jobId={selectedJobId} wsFactory={wsFactory} />
          <ReportViewer jobId={selectedJobId} />
        </div>
        <div className="col">
          <RagChatPanel jobId={selectedJobId} />
        </div>
      </main>
    </div>
  );
}
