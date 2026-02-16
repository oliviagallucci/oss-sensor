import { Routes, Route, Link } from "react-router-dom";
import QueueView from "./QueueView";
import DiffDetailView from "./DiffDetailView";

interface AppProps {
  apiBase: string;
}

export default function App({ apiBase }: AppProps) {
  return (
    <div className="app">
      <header className="header">
        <h1>OSS-Sensor</h1>
        <nav>
          <Link to="/">Queue</Link>
        </nav>
      </header>
      <main className="container">
        <Routes>
          <Route path="/" element={<QueueView apiBase={apiBase} />} />
          <Route path="/diff/:diffId" element={<DiffDetailView apiBase={apiBase} />} />
        </Routes>
      </main>
    </div>
  );
}
