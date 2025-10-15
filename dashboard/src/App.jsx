import React, {useEffect, useState} from 'react'

export default function App(){
  const [health, setHealth] = useState('unknown')
  const [running, setRunning] = useState(false)
  const [alerts, setAlerts] = useState([])
  const API_BASE = 'http://localhost:8000'

  useEffect(()=>{
    fetch(`${API_BASE}/health`).then(r=>r.json()).then(d=>setHealth(d.status)).catch(()=>setHealth('down'))
  },[])

  async function runSim(){
    setRunning(true)
    const payload = {target: 'http://localhost:8069', db: 'sandbox', user: 'admin', wordlist: ['admin','odoo','letmein'], sandbox: true}
    await fetch(`${API_BASE}/run-simulation`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)})
    setRunning(false)
  }

  async function loadAlerts(){
    const r = await fetch(`${API_BASE}/alerts/latest`); const j = await r.json(); setAlerts(j.results || [])
  }

  return (<div style={{fontFamily: 'sans-serif', padding:20}}>
    <h1>CyberSentinelAI — Dashboard (Phase1)</h1>
    <p>Backend health: <strong>{health}</strong></p>
    <button onClick={runSim} disabled={running}>{running? 'Running...':'Run Simulation'}</button>
    <button onClick={loadAlerts} style={{marginLeft:10}}>Load Alerts</button>
    <h2>Recent Alerts</h2>
    <ul>
      {alerts.map(a=> <li key={a._id || Math.random()}>{a.timestamp} — {a.event_type} — {JSON.stringify(a.payload)}</li>)}
    </ul>
  </div>)
}
