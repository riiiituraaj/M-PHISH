import './globals.css'
import { Shield } from 'lucide-react'
import Link from 'next/link'

export default function Layout({children}:{children:React.ReactNode}) { return <html lang="en"><body><header className="topbar"><Link className="brand" href="/"><span className="brandmark"><Shield size={17}/></span><span>M-PHISH <b>X</b></span></Link><nav><Link href="/investigations">Investigations</Link><Link href="/settings">Settings</Link></nav></header>{children}</body></html> }
