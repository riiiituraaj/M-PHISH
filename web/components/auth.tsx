"use client";
import { createContext, useContext, useEffect, useState } from "react";
import Link from "next/link";
import { ApiError, getSession, signOut, User } from "../lib/api";
type Session = { user: User | null; loading: boolean; error: string; refresh: () => Promise<void>; logout: () => Promise<void> };
const Context = createContext<Session>({ user: null, loading: true, error: "", refresh: async () => {}, logout: async () => {} });
export function SessionProvider({ children }: { children: React.ReactNode }) {
 const [user, setUser] = useState<User | null>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState("");
 async function refresh() { setLoading(true); setError(""); try { setUser((await getSession()).user); } catch (e) { setUser(null); if (!(e instanceof ApiError && e.status === 401)) setError(e instanceof Error ? e.message : "Session unavailable."); } finally { setLoading(false); } }
 async function logout() { try { await signOut(); setUser(null); window.location.assign("/signin"); } catch (e) { setError(e instanceof Error ? e.message : "Sign out failed."); } }
 useEffect(() => { void refresh(); }, []);
 return <Context.Provider value={{ user, loading, error, refresh, logout }}>{children}</Context.Provider>;
}
export const useSession = () => useContext(Context);
export function SessionControl() { const { user, loading, logout, error } = useSession(); return user ? <div><button className="secondary-action" onClick={() => void logout()}>Sign out</button>{error && <small role="alert">{error}</small>}</div> : <Link className="secondary-action" href="/signin">{loading ? "Checking sessionâ€¦" : "Sign in"}</Link>; }
export function RequireSession({ children }: { children: React.ReactNode }) { const { user, loading, error, refresh } = useSession(); if (loading) return <main><p role="status">Checking your sessionâ€¦</p></main>; if (!user) return <main><section className="surface setting-card"><h1>{error ? "Service unavailable" : "Sign in to continue"}</h1><p className="subtle">{error || "Your investigations and preferences are private to your account."}</p><Link className="primary-action" href="/signin">Sign in</Link>{error && <button onClick={() => void refresh()}>Retry</button>}</section></main>; return <>{children}</>; }
export function ErrorNotice({ error }: { error: unknown }) { if (!error) return null; return <div className="notice" role="alert"><p>{error instanceof Error ? error.message : String(error)}</p>{error instanceof ApiError && error.requestId && <small>Request: {error.requestId}</small>}{error instanceof ApiError && error.status === 401 && <Link href="/signin">Sign in again</Link>}</div>; }
