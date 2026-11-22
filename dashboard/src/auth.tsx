// Optional Auth0 login. Does nothing unless VITE_AUTH0_DOMAIN and VITE_AUTH0_CLIENT_ID are set at build/dev time.
// It only decides whether the person sees the dashboard and sends a bearer token; the gateway checks the token itself.
// The physical key never goes through this.
import { Auth0Provider, useAuth0 } from "@auth0/auth0-react";
import { ReactNode } from "react";
import { setTokenGetter } from "./api";

const domain = import.meta.env.VITE_AUTH0_DOMAIN as string | undefined;
const clientId = import.meta.env.VITE_AUTH0_CLIENT_ID as string | undefined;
const audience = import.meta.env.VITE_AUTH0_AUDIENCE as string | undefined;
export const authEnabled = Boolean(domain && clientId);

export function AuthProvider({ children }: { children: ReactNode }) {
  if (!authEnabled) return <>{children}</>;
  return (
    <Auth0Provider domain={domain!} clientId={clientId!} cacheLocation="memory"
      authorizationParams={{ redirect_uri: window.location.origin, ...(audience ? { audience } : {}) }}>
      {children}
    </Auth0Provider>
  );
}

/** Shows a login screen until signed in, then renders the app with a small account control. */
export function AuthGate({ children }: { children: (account: ReactNode) => ReactNode }) {
  const { isLoading, isAuthenticated, error, loginWithRedirect, logout, user, getAccessTokenSilently } = useAuth0();
  if (isLoading) return <div className="login"><div className="login-card"><p className="muted">Checking your session…</p></div></div>;
  if (!isAuthenticated) {
    return (
      <div className="login">
        <div className="login-card">
          <div className="wordmark">AIRLOCK</div>
          <p>Sign in to approve actions and rewind.</p>
          {error && <p className="login-err">{error.message}</p>}
          <button className="btn btn-primary" onClick={() => loginWithRedirect()}>Sign in</button>
          <p className="muted">The physical key does not use this login.</p>
        </div>
      </div>
    );
  }
  setTokenGetter(async () => (await getAccessTokenSilently()) ?? "");
  return (
    <>
      {children(
        <div className="account">
          <span className="muted">{user?.email ?? user?.name ?? "signed in"}</span>
          <button className="btn btn-sm" onClick={() => logout({ logoutParams: { returnTo: window.location.origin } })}>Log out</button>
        </div>,
      )}
    </>
  );
}
