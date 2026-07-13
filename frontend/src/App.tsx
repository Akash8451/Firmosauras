import { SessionProvider } from "./auth/session";
import { Dashboard } from "./components/Dashboard";
import "./index.css";

export default function App() {
  return (
    <SessionProvider initialRole="admin">
      <Dashboard />
    </SessionProvider>
  );
}
