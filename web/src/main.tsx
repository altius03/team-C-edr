import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// Fail fast when the static HTML shell is missing the mount point Vite expects.
const root = document.getElementById("root");

if (root === null) {
  throw new Error("React root element was not found");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>
);
