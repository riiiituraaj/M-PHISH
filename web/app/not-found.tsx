import Link from 'next/link'
export default function NotFound(){return <main><section className="glass panel"><div className="eyebrow">Not found</div><h1 style={{fontFamily:'Manrope'}}>Investigation not found.</h1><p className="subtle">This report may have expired or been removed.</p><Link className="back" href="/">← Back to overview</Link></section></main>}
