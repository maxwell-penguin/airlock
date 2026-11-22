import React, { lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { AuthGate, AuthProvider, authEnabled } from "./auth";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-sans/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./styles.css";

// ?kit shows the design kit: every component in every state, with made-up data. It never talks to the gateway.
const Kit = lazy(() => import("./Kit"));
const showKit = new URLSearchParams(window.location.search).has("kit");

createRoot(document.getElementById("root")!).render(
  showKit ? (
    <Suspense fallback={null}><Kit /></Suspense>
  ) : authEnabled ? (
    <AuthProvider>
      <AuthGate>{(account) => <App account={account} />}</AuthGate>
    </AuthProvider>
  ) : (
    <App />
  ),
);
