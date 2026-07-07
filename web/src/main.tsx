import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// 정적 HTML 셸에 Vite가 기대하는 마운트 지점이 없으면 즉시 실패합니다.
const root = document.getElementById("root");

if (root === null) {
  throw new Error("React root element was not found");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>
);
