"use client";

import "./globals.css";
import { Activity, FlaskConical, Shield } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export default function Layout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <Link className="brand" href="/">
            <span className="brandmark">
              <Shield size={17} />
            </span>
            <span>
              M-PHISH <b>X</b>
            </span>
          </Link>
          <nav aria-label="Primary navigation">
            <Link className={pathname === "/" ? "active" : ""} href="/">Dashboard</Link>
            <Link className={pathname.startsWith("/investigations") ? "active" : ""} href="/investigations">Investigations</Link>
            <Link className={pathname.startsWith("/research") ? "active" : ""} href="/research">Research</Link>
            <Link className={pathname.startsWith("/settings") ? "active" : ""} href="/settings">Settings</Link>
          </nav>
          <span className="system-state">
            <Activity size={13} /> Digital Trust Engine v1.0
          </span>
        </header>
        {children}
      </body>
    </html>
  );
}
