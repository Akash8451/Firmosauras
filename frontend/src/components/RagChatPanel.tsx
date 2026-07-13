import { useState } from "react";
import { useSession } from "../auth/session";
import { cveChat } from "../api/client";
import type { ChatResponse } from "../api/types";

interface Turn {
  question: string;
  response: ChatResponse | null;
  error: string | null;
}

// Scoped RAG chat. It ALWAYS shows which job_id it is scoped to (cross-job
// isolation is enforced server-side, Task 14; the banner makes the scope explicit
// so an analyst never confuses one firmware's answers for another's). Retrieval
// is air-gapped; `grounded=false` / no sources is surfaced honestly.
export function RagChatPanel({ jobId }: { jobId: string | null }) {
  const { token } = useSession();
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [busy, setBusy] = useState(false);

  if (!jobId) {
    return (
      <section className="panel" aria-label="rag chat">
        <h2>Ask about this job</h2>
        <p className="muted">Select a job to chat about its findings.</p>
      </section>
    );
  }

  async function ask(e: React.FormEvent) {
    e.preventDefault();
    const q = question.trim();
    if (!q || !jobId) return;
    setBusy(true);
    setQuestion("");
    try {
      const response = await cveChat({ job_id: jobId, question: q }, token);
      setTurns((prev) => [...prev, { question: q, response, error: null }]);
    } catch (err) {
      setTurns((prev) => [
        ...prev,
        { question: q, response: null, error: err instanceof Error ? err.message : String(err) },
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-label="rag chat">
      <h2>Ask about this job</h2>
      <p className="scope-banner" data-testid="chat-scope">
        Scoped to job <code>{jobId}</code>
      </p>

      <ol className="chat-log">
        {turns.map((t, i) => (
          <li key={i} className="chat-turn">
            <p className="chat-q">
              <strong>Q:</strong> {t.question}
            </p>
            {t.error ? (
              <p className="error" role="alert">
                {t.error}
              </p>
            ) : (
              <div className="chat-a">
                <p>
                  <strong>A:</strong>{" "}
                  {t.response?.answer ?? (
                    <em className="muted">
                      (LLM narration unavailable — grounded sources shown below)
                    </em>
                  )}
                </p>
                <p className="grounded-flag" data-testid="grounded-flag">
                  {t.response?.grounded ? "grounded in local corpus" : "no grounding found"}
                </p>
                {t.response && t.response.sources.length > 0 && (
                  <ul className="sources">
                    {t.response.sources.map((s) => (
                      <li key={s}>
                        <code>{s}</code>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </li>
        ))}
      </ol>

      <form onSubmit={ask} className="chat-input">
        <input
          type="text"
          aria-label="chat question"
          placeholder="e.g. which findings are exploitable?"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          disabled={busy}
        />
        <button type="submit" disabled={busy || question.trim().length === 0}>
          {busy ? "Asking…" : "Ask"}
        </button>
      </form>
    </section>
  );
}
