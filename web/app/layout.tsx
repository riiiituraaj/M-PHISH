"use client";
import "./globals.css";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { SessionControl, SessionProvider, useSession } from "../components/auth";
function Navigation() { const path = usePathname(); const { user } = useSession(); return <header className="topbar"><Link className="brand" href="/">M-PHISH <b>X</b></Link><nav aria-label="Primary navigation">{[["/", "Overview"], ["/investigations", "Investigations"], ["/research", "Research"], ["/demo", "Demo"], ["/settings", "Settings"], ...(user?.role === "admin" ? [["/admin", "Operations"]] : [])].map(([href, label]) => <Link key={href} className={path === href ? "active" : ""} aria-current={path === href ? "page" : undefined} href={href}>{label}</Link>)}</nav><SessionControl /></header>; }
export default function Layout({ children }: { children: React.ReactNode }) { return <html lang="en"><body><SessionProvider><a className="skip-link" href="#main-content">Skip to content</a><Navigation /><div id="main-content">{children}</div><footer className="site-footer">Evidence-based website checks. An assessment is not a guarantee of safety. <Link href="/privacy">Privacy and limitations</Link></footer></SessionProvider></body></html>; }
