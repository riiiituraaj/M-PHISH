'use client'
import {useEffect,useState} from 'react'
import {ArrowRight,Search} from 'lucide-react'
import {useRouter} from 'next/navigation'
import {investigate,listInvestigations,Report} from '../lib/api'

export default function Home(){
  const [url,setUrl]=useState('');const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [recent,setRecent]=useState<Report[]>([]);const router=useRouter()
  useEffect(()=>{listInvestigations().then(items=>setRecent(items.slice(0,5))).catch(()=>setRecent([]))},[])
  async function submit(){if(!url.trim())return;setBusy(true);setError('');try{const report=await investigate(url);router.push(`/investigations/${report.id}`)}catch(e){setError(e instanceof Error?e.message:'The investigation could not be started.')}finally{setBusy(false)}}
  return <main><section className="hero"><div className="eyebrow">Contextual digital threat intelligence</div><h1>Understand what<br/>you're seeing.</h1><p>Investigate suspicious websites before you trust them.</p><div className="search"><input aria-label="Website URL" placeholder="Paste a URL to investigate" value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==='Enter'&&submit()}/><button onClick={submit} disabled={busy}>{busy?'Investigating...':<>Investigate <Search size={15}/></>}</button></div>{error&&<p role="alert" className="form-error">{error}</p>}<div className="flow"><span>Detect <i>→</i></span><span>Understand <i>→</i></span><span>Decide</span></div></section><section><div className="section-head"><h2>Recent investigations</h2><a className="subtle" href="/investigations">View all <ArrowRight size={13}/></a></div><div className="glass recent">{recent.length?recent.map(r=><a className="recent-row" href={`/investigations/${r.id}`} key={r.id}><div><div className="url">{r.hostname}</div><div className="date">{r.created_at?new Date(r.created_at).toLocaleString():'Completed investigation'}</div></div><span className="risk-pill">{r.risk_score} / 100 · {r.classification}</span></a>):<div className="empty">No investigations yet. Start one above.</div>}</div></section></main>
}
