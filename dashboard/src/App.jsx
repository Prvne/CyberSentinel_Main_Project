import React, { useEffect, useState } from 'react'

export default function App() {
  const API_BASE = 'http://localhost:8000'
  const [health, setHealth] = useState('unknown')
  const [running, setRunning] = useState(false)
  const [rawAlerts, setRawAlerts] = useState([])
  const [derived, setDerived] = useState([])
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterType, setFilterType] = useState('')
  const [expanded, setExpanded] = useState({})
  const [related, setRelated] = useState({})

  // simulation form state
  const [simType, setSimType] = useState('brute_force')
  const [target, setTarget] = useState('http://localhost:8069')
  const [db, setDb] = useState('demo')
  const [user, setUser] = useState('admin')
  const [delay, setDelay] = useState(0.1)
  const [attempts, setAttempts] = useState(5)
  const [wordlist, setWordlist] = useState('admin,odoo,letmein')
  const [scanPorts, setScanPorts] = useState('22,80,443,8080')
  const [payloads, setPayloads] = useState("' OR '1'='1")
  const [hosts, setHosts] = useState('10.0.0.5,10.0.0.7')
  const [users, setUsers] = useState('user1,user2,user3')
  const [password, setPassword] = useState('Summer2025!')
  const [dataSize, setDataSize] = useState(120)
  const [chunkSize, setChunkSize] = useState(40)
  const [paths, setPaths] = useState('../../etc/passwd,..%2f..%2f..%2fwindows/win.ini')

  useEffect(() => {
    fetch(`${API_BASE}/health`).then(r => r.json()).then(d => setHealth(d.status)).catch(() => setHealth('down'))
  }, [])

  function buildPayload() {
    const base = { target, db, user, delay: Number(delay), sandbox: true, sim_type: simType }
    switch (simType) {
      case 'brute_force':
        return { ...base, wordlist: wordlist.split(',').map(s => s.trim()).filter(Boolean) }
      case 'port_scan':
        return { ...base, scan_ports: scanPorts.split(',').map(s => Number(s.trim())).filter(n => !Number.isNaN(n)), attempts: Number(attempts) }
      case 'sql_injection':
      case 'xss_probe':
      case 'csrf_probe':
      case 'command_injection':
      case 'file_upload_probe':
      case 'ssrf_probe':
      case 'jwt_tamper':
      case 'web_cache_deception':
        return { ...base, payloads: payloads.split(',').map(s => s.trim()).filter(Boolean), attempts: Number(attempts) }
      case 'phishing':
      case 'ddos':
      case 'malware_beacon':
      case 'ransomware':
        return { ...base, attempts: Number(attempts) }
      case 'lateral_movement':
        return { ...base, hosts: hosts.split(',').map(s => s.trim()).filter(Boolean), attempts: Number(attempts) }
      case 'data_exfiltration':
        return { ...base, data_size_kb: Number(dataSize), chunk_size_kb: Number(chunkSize) }
      case 'password_spray':
        return { ...base, users: users.split(',').map(s => s.trim()).filter(Boolean), password }
      case 'directory_traversal':
        return { ...base, paths: paths.split(',').map(s => s.trim()).filter(Boolean), attempts: Number(attempts) }
      case 'credential_stuffing':
        return { ...base, users: users.split(',').map(s => s.trim()).filter(Boolean), payloads: payloads.split(',').map(s => s.trim()).filter(Boolean), attempts: Number(attempts) }
      default:
        return base
    }
  }

  async function runSim() {
    setRunning(true)
    try {
      const payload = buildPayload()
      await fetch(`${API_BASE}/run-simulation`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    } finally {
      setRunning(false)
    }
  }

  async function loadRaw() {
    const r = await fetch(`${API_BASE}/alerts/latest`); const j = await r.json(); setRawAlerts(j.results || [])
  }
  async function loadDerived() {
    const params = new URLSearchParams()
    params.set('window_minutes', '120')
    if (filterSeverity) params.set('severity', filterSeverity)
    if (filterType) params.set('type_contains', filterType)
    const r = await fetch(`${API_BASE}/alerts/derived?${params.toString()}`); const j = await r.json(); setDerived(j.results || [])
  }

  async function loadRelated(alertType) {
    const r = await fetch(`${API_BASE}/alerts/related?alert_type=${encodeURIComponent(alertType)}&limit=10&window_minutes=120`)
    const j = await r.json()
    setRelated(prev => ({ ...prev, [alertType]: j.results || [] }))
  }

  function toggleExpand(alert) {
    const key = `${alert.type}`
    const isOpen = !!expanded[key]
    const next = { ...expanded, [key]: !isOpen }
    setExpanded(next)
    if (!isOpen && !related[key]) {
      loadRelated(alert.type)
    }
  }

  const label = { display: 'block', fontSize: 13, color: '#374151', marginBottom: 4 }
  const input = { padding: 6, border: '1px solid #d1d5db', borderRadius: 6, width: '100%' }
  const col = { flex: 1, minWidth: 320, marginRight: 16 }
  const card = { border: '1px solid #e5e7eb', borderRadius: 10, padding: 16, marginTop: 16, background: '#fff' }

  function sevColor(sev) {
    switch ((sev || '').toLowerCase()) {
      case 'high': return '#ef4444'
      case 'medium': return '#f59e0b'
      case 'low': return '#10b981'
      default: return '#6b7280'
    }
  }

  return (
    <div style={{ fontFamily: 'system-ui, Arial, sans-serif', padding: 20, maxWidth: 1200, margin: '0 auto', background: '#f9fafb' }}>
      <h1 style={{ marginBottom: 4 }}>CyberSentinelAI — Dashboard</h1>
      <p>Backend health: <strong>{health}</strong></p>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div style={col}>
          <div style={card}>
            <h3>Simulation</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={label}>sim_type</label>
                <select value={simType} onChange={e => setSimType(e.target.value)} style={{ ...input, height: 34 }}>
                  <option value="brute_force">brute_force</option>
                  <option value="port_scan">port_scan</option>
                  <option value="sql_injection">sql_injection</option>
                  <option value="xss_probe">xss_probe</option>
                  <option value="csrf_probe">csrf_probe</option>
                  <option value="command_injection">command_injection</option>
                  <option value="file_upload_probe">file_upload_probe</option>
                  <option value="ssrf_probe">ssrf_probe</option>
                  <option value="jwt_tamper">jwt_tamper</option>
                  <option value="phishing">phishing</option>
                  <option value="ddos">ddos</option>
                  <option value="data_exfiltration">data_exfiltration</option>
                  <option value="ransomware">ransomware</option>
                  <option value="lateral_movement">lateral_movement</option>
                  <option value="malware_beacon">malware_beacon</option>
                  <option value="password_spray">password_spray</option>
                  <option value="directory_traversal">directory_traversal</option>
                  <option value="credential_stuffing">credential_stuffing</option>
                  <option value="web_cache_deception">web_cache_deception</option>
                </select>
              </div>
              <div>
                <label style={label}>delay (s)</label>
                <input value={delay} onChange={e => setDelay(e.target.value)} style={input} />
              </div>
              <div>
                <label style={label}>target</label>
                <input value={target} onChange={e => setTarget(e.target.value)} style={input} />
              </div>
              <div>
                <label style={label}>db</label>
                <input value={db} onChange={e => setDb(e.target.value)} style={input} />
              </div>
              <div>
                <label style={label}>user</label>
                <input value={user} onChange={e => setUser(e.target.value)} style={input} />
              </div>
              <div>
                <label style={label}>attempts</label>
                <input value={attempts} onChange={e => setAttempts(e.target.value)} style={input} />
              </div>
            </div>

            {simType === 'brute_force' && (
              <div style={{ marginTop: 12 }}>
                <label style={label}>wordlist (comma separated)</label>
                <input value={wordlist} onChange={e => setWordlist(e.target.value)} style={input} />
              </div>
            )}
            {simType === 'port_scan' && (
              <div style={{ marginTop: 12 }}>
                <label style={label}>scan_ports (comma separated)</label>
                <input value={scanPorts} onChange={e => setScanPorts(e.target.value)} style={input} />
              </div>
            )}
            {(simType === 'sql_injection' || simType === 'xss_probe' || simType === 'csrf_probe' || simType === 'command_injection' || simType === 'file_upload_probe' || simType === 'ssrf_probe' || simType === 'jwt_tamper' || simType === 'web_cache_deception') && (
              <div style={{ marginTop: 12 }}>
                <label style={label}>payloads (comma separated)</label>
                <input value={payloads} onChange={e => setPayloads(e.target.value)} style={input} />
              </div>
            )}
            {simType === 'credential_stuffing' && (
              <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={label}>users (comma separated)</label>
                  <input value={users} onChange={e => setUsers(e.target.value)} style={input} />
                </div>
                <div>
                  <label style={label}>payloads (password list)</label>
                  <input value={payloads} onChange={e => setPayloads(e.target.value)} style={input} />
                </div>
              </div>
            )}
            {simType === 'lateral_movement' && (
              <div style={{ marginTop: 12 }}>
                <label style={label}>hosts (comma separated)</label>
                <input value={hosts} onChange={e => setHosts(e.target.value)} style={input} />
              </div>
            )}
            {simType === 'data_exfiltration' && (
              <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={label}>data_size_kb</label>
                  <input value={dataSize} onChange={e => setDataSize(e.target.value)} style={input} />
                </div>
                <div>
                  <label style={label}>chunk_size_kb</label>
                  <input value={chunkSize} onChange={e => setChunkSize(e.target.value)} style={input} />
                </div>
              </div>
            )}
            {simType === 'password_spray' && (
              <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={label}>users (comma separated)</label>
                  <input value={users} onChange={e => setUsers(e.target.value)} style={input} />
                </div>
                <div>
                  <label style={label}>password</label>
                  <input value={password} onChange={e => setPassword(e.target.value)} style={input} />
                </div>
              </div>
            )}
            {simType === 'directory_traversal' && (
              <div style={{ marginTop: 12 }}>
                <label style={label}>paths (comma separated)</label>
                <input value={paths} onChange={e => setPaths(e.target.value)} style={input} />
              </div>
            )}

            <div style={{ marginTop: 16 }}>
              <button onClick={runSim} disabled={running} style={{ padding: '8px 12px', borderRadius: 8, border: '1px solid #0ea5e9', background: '#0ea5e9', color: '#fff' }}>
                {running ? 'Running...' : 'Run Simulation'}
              </button>
            </div>
          </div>
        </div>

        <div style={{ ...col, minWidth: 360 }}>
          <div style={card}>
            <h3>Derived Alerts</h3>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' }}>
              <button onClick={loadDerived} style={{ padding: '6px 10px', borderRadius: 8, border: '1px solid #e5e7eb' }}>Refresh</button>
              <div>
                <label style={{ fontSize: 12, color: '#374151', marginRight: 6 }}>Severity</label>
                <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} style={{ padding: 6, border: '1px solid #d1d5db', borderRadius: 6 }}>
                  <option value=''>All</option>
                  <option value='high'>High</option>
                  <option value='medium'>Medium</option>
                  <option value='low'>Low</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 12, color: '#374151', marginRight: 6 }}>Type</label>
                <input value={filterType} onChange={e => setFilterType(e.target.value)} placeholder="contains..." style={{ padding: 6, border: '1px solid #d1d5db', borderRadius: 6 }} />
              </div>
            </div>
            <div style={{ maxHeight: 280, overflow: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', borderBottom: '1px solid #e5e7eb', padding: 6 }}>severity</th>
                    <th style={{ textAlign: 'left', borderBottom: '1px solid #e5e7eb', padding: 6 }}>type</th>
                    <th style={{ textAlign: 'left', borderBottom: '1px solid #e5e7eb', padding: 6 }}>detail</th>
                    <th style={{ textAlign: 'left', borderBottom: '1px solid #e5e7eb', padding: 6 }}>actions</th>
                  </tr>
                </thead>
                <tbody>
                  {derived
                    .filter(a => !filterSeverity || (a.severity || '').toLowerCase() === filterSeverity)
                    .filter(a => !filterType || (a.type || '').toLowerCase().includes(filterType.toLowerCase()))
                    .map((a, idx) => (
                      <>
                        <tr key={`row-${idx}`}>
                          <td style={{ padding: 6 }}>
                            <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, backgroundColor: sevColor(a.severity), color: '#fff', fontSize: 12 }}>{a.severity}</span>
                          </td>
                          <td style={{ padding: 6 }}>{a.type}</td>
                          <td style={{ padding: 6 }}><code style={{ fontSize: 12 }}>{JSON.stringify(a.detail)}</code></td>
                          <td style={{ padding: 6 }}>
                            <button onClick={() => toggleExpand(a)} style={{ padding: '4px 8px', borderRadius: 6, border: '1px solid #d1d5db' }}>
                              {expanded[a.type] ? 'Hide events' : 'Show events'}
                            </button>
                          </td>
                        </tr>
                        {expanded[a.type] && (
                          <tr key={`exp-${idx}`}>
                            <td colSpan={4} style={{ background: '#f3f4f6', padding: 8 }}>
                              <div style={{ fontSize: 12, color: '#374151', marginBottom: 6 }}>Related raw events</div>
                              <ul style={{ margin: 0, paddingLeft: 16, maxHeight: 160, overflow: 'auto' }}>
                                {(related[a.type] || []).map(ev => (
                                  <li key={ev._id || Math.random()}><strong>{ev.event_type}</strong> — <code>{JSON.stringify(ev.payload)}</code></li>
                                ))}
                                {(!related[a.type] || related[a.type].length === 0) && (
                                  <li style={{ color: '#6b7280' }}>No events yet...</li>
                                )}
                              </ul>
                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                </tbody>
              </table>
            </div>
          </div>

          <div style={card}>
            <h3>Raw Events (latest)</h3>
            <div style={{ marginBottom: 8 }}>
              <button onClick={loadRaw} style={{ padding: '6px 10px', borderRadius: 8, border: '1px solid #e5e7eb' }}>Refresh</button>
            </div>
            <div style={{ maxHeight: 260, overflow: 'auto' }}>
              <ul style={{ margin: 0, paddingLeft: 16 }}>
                {rawAlerts.map((a) => (
                  <li key={a._id || Math.random()} style={{ marginBottom: 6 }}>
                    <strong>{a.event_type}</strong> — <code style={{ fontSize: 12 }}>{JSON.stringify(a.payload)}</code>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
