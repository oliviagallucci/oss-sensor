import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./index.css";

const API_BASE = import.meta.env.VITE_API_URL || "/api";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App apiBase={API_BASE} />
    </BrowserRouter>
  </React.StrictMode>
);
