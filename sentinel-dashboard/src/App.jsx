import { useState, useEffect, useRef, useCallback } from 'react'

const WS_PROTOCOL = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
const WS_URL   = `${WS_PROTOCOL}//${window.location.host}/ws`
const API_BASE = '/api'

function useSentinelWS(onMessage) {
  const wsRef = useRef(null); const retryRef = useRef(null)
  const [wsStatus, setWsStatus] = useState('connecting')
  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(WS_URL); wsRef.current = ws
      ws.onopen = () => { setWsStatus('online'); clearTimeout(retryRef.current) }
      ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
      ws.onclose = () => { setWsStatus('reconnecting'); retryRef.current = setTimeout(connect, 3000) }
      ws.onerror = () => { setWsStatus('error'); ws.close() }
    } catch { setWsStatus('error'); retryRef.current = setTimeout(connect, 3000) }
  }, [onMessage])
  useEffect(() => { connect(); return () => { clearTimeout(retryRef.current); wsRef.current?.close() } }, [connect])
  return wsStatus
}

function fmtTime(iso) { return new Date(iso || Date.now()).toLocaleTimeString('en-US', { hour12: false }) }
function useNow() {
  const [now, setNow] = useState(new Date())
  useEffect(() => { const id = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(id) }, [])
  return now
}

// ── Threat Entry ──────────────────────────────────────────────────────────────
function ThreatEntry({ entry }) {
  const isDefense = entry.entryType === 'defense'
  const isRetaliation = entry.entryType === 'retaliation'
  const cls = isRetaliation ? 'retaliation-entry' : isDefense ? 'defense-entry' : (entry.severity || 'MEDIUM')
  return (
    <div className={`threat-entry ${cls}`}>
      <div className="threat-time">{fmtTime(entry.timestamp)}</div>
      <div className="threat-type">
        {isRetaliation ? '⚡ ' : isDefense ? '🛡 ' : '🔴 '}
        {entry.attack_type || entry.action || entry.message?.slice(0,40) || 'EVENT'}
      </div>
      <div className="threat-meta">
        {(entry.source_ip || entry.blocked_ip || entry.attacker_ip) &&
          <span className="threat-ip">{entry.source_ip || entry.blocked_ip || entry.attacker_ip}</span>}
        {entry.target_service && <span>→ {entry.target_service}</span>}
        {entry.service_protected && <span>→ {entry.service_protected}</span>}
        {!isDefense && !isRetaliation && entry.severity &&
          <span className={`severity-badge ${entry.severity}`}>{entry.severity}</span>}
        {isDefense && <span className="severity-badge DEFENSE">BLOCKED</span>}
        {isRetaliation && <span className="severity-badge RETALIATE">COUNTER</span>}
      </div>
      {(entry.ai_analysis || entry.message) &&
        <div className="threat-ai">{entry.ai_analysis || entry.message}</div>}
    </div>
  )
}

function ThreatFeed({ entries }) {
  const bottomRef = useRef(null)
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [entries])
  return (
    <div className="panel-body threat-feed">
      {entries.length === 0
        ? <div className="feed-empty"><div className="feed-empty-icon">📡</div><div>MONITORING NETWORK TRAFFIC</div><div style={{color:'var(--gray)',fontSize:9,letterSpacing:2}}>AWAITING THREAT ACTIVITY</div></div>
        : entries.map((e, i) => <ThreatEntry key={i} entry={e} />)}
      <div ref={bottomRef} />
    </div>
  )
}

// ── Radar ─────────────────────────────────────────────────────────────────────
function Radar({ underAttack, retaliationActive }) {
  const color = retaliationActive ? 'var(--purple)' : underAttack ? 'var(--red)' : 'var(--cyan)'
  const speed = underAttack || retaliationActive ? '1s' : '3s'
  return (
    <div className="radar-container">
      {[250, 190, 130, 70].map((d, i) => (
        <div key={i} className="radar-ring" style={{
          width:d, height:d,
          borderColor:`${color}${['18','28','38','55'][i]}`,
        }} />
      ))}
      <div style={{position:'absolute',inset:0,borderRadius:'50%',overflow:'hidden'}}>
        <div className="radar-sweep-line" style={{
          position:'absolute',top:'50%',left:'50%',width:'50%',height:'2px',
          transformOrigin:'left center',
          background:`linear-gradient(90deg,transparent,${color}dd)`,
          animation:`scan-line ${speed} linear infinite`,
        }} />
      </div>
      {[250,180,110].map((d, i) => (
        <div key={i} className="radar-ping" style={{
          borderColor:color,
          animationDuration:underAttack || retaliationActive ? '.9s' : '2.5s',
          animationDelay:`${i * (underAttack ? .3 : .8)}s`,
          opacity:underAttack ? .9 : .35,
        }} />
      ))}
      <div style={{position:'absolute',top:'50%',left:'50%',width:10,height:10,borderRadius:'50%',
        background:color,transform:'translate(-50%,-50%)',boxShadow:`0 0 16px ${color}`}} />
      <div style={{position:'absolute',top:'50%',left:'50%',transform:'translate(-50%,55px)',
        fontFamily:'var(--font-hud)',fontSize:9,letterSpacing:3,color,
        animation:underAttack || retaliationActive ? 'blink .6s infinite' : 'none',textTransform:'uppercase'}}>
        {retaliationActive ? '⚡ RETALIATING' : underAttack ? '⚠ UNDER ATTACK' : '● MONITORING'}
      </div>
    </div>
  )
}

function NetworkNode({ icon, label, status }) {
  const color = status==='safe' ? 'var(--green)' : status==='danger' ? 'var(--red)' : 'var(--amber)'
  return (
    <div className="network-node">
      <div className={`node-orb ${status}`}>{icon}</div>
      <div className="node-label" style={{color}}>{label}</div>
      <div className="node-status">{status.toUpperCase()}</div>
    </div>
  )
}

// ── Attacker Profile + Retaliation Panel ──────────────────────────────────────
function AttackerPanel({ profile, honeypotEvents, retaliationSteps, retaliationActive }) {
  const hasData = profile?.ip

  if (!hasData && retaliationSteps.length === 0) {
    return (
      <div className="panel-body">
        <div className="profile-empty">
          <div className="profile-empty-icon">🎯</div>
          <div className="profile-empty-text">AWAITING<br/>THREAT<br/>INTELLIGENCE</div>
          <div style={{fontSize:8,letterSpacing:2,color:'var(--gray)',fontFamily:'var(--font-mono)',textAlign:'center'}}>
            ENGAGE HONEYPOT TO<br/>BEGIN PROFILING
          </div>
        </div>
      </div>
    )
  }

  const score = profile?.threat_score || 0
  const tools = [...new Set(profile?.tools || [])]
  const commands = profile?.commands || []
  const services = profile?.services_hit || []
  const scoreColor = score >= 75 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : 'var(--green)'
  const isExposed = score >= 50 || profile?.dossier

  return (
    <div className="panel-body" style={{overflow:'auto'}}>
      {isExposed && <div className="profile-exposed">⚠ ATTACKER EXPOSED</div>}
      {retaliationActive && <div className="retaliation-badge">⚡ COUNTERATTACK IN PROGRESS</div>}
      {profile?.dossier && !retaliationActive && <div className="retaliation-badge">✓ COUNTERATTACK COMPLETE</div>}

      {/* Threat Score */}
      {score > 0 && (
        <div className="threat-score-container">
          <div className="threat-score-label">
            <span>THREAT SCORE</span>
            <span style={{color:scoreColor,fontFamily:'var(--font-hud)',fontSize:13,fontWeight:900}}>{score}/100</span>
          </div>
          <div className="threat-score-bar-bg">
            <div className="threat-score-bar-fill" style={{
              width:`${score}%`, position:'relative',
              background:`linear-gradient(90deg,var(--green-dim),${scoreColor})`,
              boxShadow:`0 0 10px ${scoreColor}`,
            }} />
          </div>
        </div>
      )}

      <div className="divider" />

      {/* Basic profile */}
      {profile?.ip && (
        <>
          <div className="profile-field">
            <div className="profile-field-label">ATTACKER IP</div>
            <div className="profile-field-value">{profile.ip}</div>
          </div>
          <div className="profile-field">
            <div className="profile-field-label">OS FINGERPRINT</div>
            <div className="profile-field-value">{profile.os || 'Linux / Kali (detected from attack pattern)'}</div>
          </div>
          {profile.mac && profile.mac !== 'Unknown' && (
            <div className="profile-field">
              <div className="profile-field-label">MAC ADDRESS</div>
              <div className="profile-field-value" style={{color:'var(--amber)'}}>{profile.mac}</div>
            </div>
          )}
          <div className="profile-field">
            <div className="profile-field-label">BEHAVIOR PATTERN</div>
            <div className="profile-field-value">Systematic enumeration → brute force → exploitation</div>
          </div>
          {tools.length > 0 && (
            <div className="profile-field">
              <div className="profile-field-label">ATTACK TOOLS DETECTED</div>
              <div style={{marginTop:4}}>
                {tools.map((t,i) => <span key={i} className="tool-badge">{t}</span>)}
              </div>
            </div>
          )}
          {services.length > 0 && (
            <div className="profile-field">
              <div className="profile-field-label">SERVICES ATTACKED</div>
              <div className="profile-field-value">{services.join(' → ')}</div>
            </div>
          )}
        </>
      )}

      {/* Retaliation steps streaming in */}
      {retaliationSteps.length > 0 && (
        <>
          <div className="divider" />
          <div className="profile-field-label" style={{marginBottom:6}}>COUNTERATTACK LOG</div>
          {retaliationSteps.map((step, i) => (
            <div key={i} className="retaliation-step">
              <div className="retaliation-step-label">
                {step.phase === 'TRACE' ? '📡 TRACING ROUTE' :
                 step.phase === 'TRACE_COMPLETE' ? '✓ ROUTE MAPPED' :
                 step.phase === 'SCAN' ? '🔍 SCANNING ATTACKER' :
                 step.phase === 'SCAN_COMPLETE' ? '✓ SCAN COMPLETE' :
                 step.phase === 'DOSSIER' ? '🧠 GENERATING DOSSIER' :
                 step.phase === 'EXPOSED' ? '🎯 ATTACKER EXPOSED' : step.phase}
              </div>
              <div className="retaliation-step-text">{step.message}</div>
              {step.hops && step.hops.length > 0 && (
                <div style={{marginTop:4}}>
                  {step.hops.slice(0,4).map((h,j) => (
                    <div key={j} style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--cyan)',marginBottom:1}}>› {h}</div>
                  ))}
                </div>
              )}
              {step.open_ports && step.open_ports.length > 0 && (
                <div style={{marginTop:4}}>
                  {step.open_ports.map((p,j) => <div key={j} className="port-entry">› {p}</div>)}
                </div>
              )}
            </div>
          ))}
        </>
      )}

      {/* Commands captured */}
      {commands.length > 0 && (
        <>
          <div className="divider" />
          <div className="profile-field">
            <div className="profile-field-label">COMMANDS / PAYLOADS CAPTURED</div>
            <div style={{marginTop:4,maxHeight:120,overflowY:'auto'}}>
              {commands.slice(-6).map((cmd,i) => (
                <div key={i} className="command-entry">
                  <span className="command-prompt">$</span>{cmd}
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* AI Dossier */}
      {profile?.dossier && (
        <div className="dossier-box">
          <div className="dossier-title">⚡ AI THREAT DOSSIER</div>
          <div className="dossier-text">{profile.dossier}</div>
        </div>
      )}

      {/* Honeypot intel ticker */}
      {honeypotEvents.slice(-2).map((ev,i) => (
        <div key={i} className="hp-ticker">
          <span className="hp-ticker-tag">INTEL</span>
          <span className="hp-ticker-text">{ev.service} — {ev.tool_detected || 'probe'} — {ev.payload?.slice(0,50) || '...'}</span>
        </div>
      ))}
    </div>
  )
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const now = useNow()
  const [feedEntries,      setFeedEntries]      = useState([])
  const [stats,            setStats]            = useState({ attacks_detected:0, attacks_blocked:0, active_threats:0 })
  const [nodeStates,       setNodeStates]       = useState({ DATABASE:'safe', 'API SERVER':'safe', 'AUTH SERVER':'safe' })
  const [underAttack,      setUnderAttack]      = useState(false)
  const [attackDetected,   setAttackDetected]   = useState(false)
  const [honeypotActive,   setHoneypotActive]   = useState(false)
  const [profile,          setProfile]          = useState(null)
  const [honeypotEvents,   setHoneypotEvents]   = useState([])
  const [simRunning,       setSimRunning]       = useState(false)
  const [retaliationActive,setRetaliationActive]= useState(false)
  const [retaliationSteps, setRetaliationSteps] = useState([])
  const clearAttackRef = useRef(null)

  const handleMessage = useCallback((msg) => {
    const { type, data } = msg

    if (type === 'init') {
      setStats(data.stats || {}); setHoneypotActive(data.honeypot_active || false); return
    }

    if (type === 'attack') {
      setStats(data.stats || {}); setAttackDetected(true); setUnderAttack(true)
      clearTimeout(clearAttackRef.current)
      clearAttackRef.current = setTimeout(() => setUnderAttack(false), 6000)
      const svc = (data.target_service || '').toUpperCase()
      setNodeStates(prev => {
        const n = {...prev}
        if (svc.includes('DATABASE'))   n.DATABASE = 'danger'
        if (svc.includes('API'))        n['API SERVER'] = 'danger'
        if (svc.includes('AUTH'))       n['AUTH SERVER'] = 'danger'
        if (svc.includes('ALL'))        { n.DATABASE = 'danger'; n['API SERVER'] = 'danger'; n['AUTH SERVER'] = 'danger' }
        return n
      })
      setFeedEntries(prev => [{ ...data, entryType:'attack' }, ...prev].slice(0, 100))
    }

    if (type === 'defense') {
      setStats(data.stats || {}); setUnderAttack(false)
      const svc = (data.service_protected || '').toUpperCase()
      setNodeStates(prev => {
        const n = {...prev}
        if (svc.includes('DATABASE'))  n.DATABASE = 'defended'
        if (svc.includes('API'))       n['API SERVER'] = 'defended'
        if (svc.includes('AUTH'))      n['AUTH SERVER'] = 'defended'
        if (svc.includes('ALL') || data.action?.includes('HONEYPOT'))
          { n.DATABASE = 'defended'; n['API SERVER'] = 'defended'; n['AUTH SERVER'] = 'defended' }
        return n
      })
      setTimeout(() => setNodeStates(prev => {
        const n = {...prev}
        Object.keys(n).forEach(k => { if (n[k] === 'defended') n[k] = 'safe' })
        return n
      }), 9000)
      setFeedEntries(prev => [{ ...data, entryType:'defense' }, ...prev].slice(0, 100))
    }

    if (type === 'honeypot') {
      setHoneypotEvents(prev => [...prev, data].slice(-20))
      const intel = data.intel_update || {}
      setProfile(prev => {
        const tools = new Set([...(prev?.tools || []), ...(intel.tools || []), data.tool_detected].filter(Boolean))
        const commands = [...(prev?.commands || []), intel.command].filter(Boolean).slice(-20)
        const services = [...new Set([...(prev?.services_hit || []), ...(intel.services_hit || []), data.service].filter(Boolean))]
        return { ...prev, ip: intel.ip || prev?.ip, threat_score: intel.threat_score || prev?.threat_score || 0, tools: [...tools], commands, services_hit: services }
      })
    }

    if (type === 'retaliation') {
      setRetaliationActive(data.phase !== 'EXPOSED')
      setRetaliationSteps(prev => [...prev, data].slice(-12))
      setFeedEntries(prev => [{ ...data, entryType:'retaliation', attack_type: `RETALIATE — ${data.phase}` }, ...prev].slice(0, 100))
      if (data.phase === 'EXPOSED') {
        setProfile(prev => ({
          ...prev,
          ip: data.attacker_ip || prev?.ip,
          os: data.os_detected || prev?.os,
          mac: data.mac_address,
          open_ports: data.open_ports,
          dossier: data.dossier,
          threat_score: data.threat_score || prev?.threat_score,
          tools: data.tools || prev?.tools || [],
          services_hit: data.services_hit || prev?.services_hit || [],
        }))
      }
    }
  }, [])

  const wsStatus = useSentinelWS(handleMessage)

  async function simulateAttack() {
    if (simRunning) return; setSimRunning(true)
    try {
      await fetch(`${API_BASE}/simulate`, { method:'POST' })
    } catch {
      const events = [
        {type:'attack',data:{timestamp:new Date().toISOString(),attack_type:'PORT_SCAN',source_ip:'185.220.101.47',target_service:'ALL SERVICES',severity:'HIGH',ai_analysis:'Aggressive port scan detected — attacker mapping all network services.',stats:{attacks_detected:1,attacks_blocked:0,active_threats:1}}},
        {type:'attack',data:{timestamp:new Date().toISOString(),attack_type:'BRUTE_FORCE',source_ip:'45.142.212.100',target_service:'SSH (AUTH SERVER)',severity:'CRITICAL',ai_analysis:'SSH brute force in progress — 1200 attempts per minute using rockyou.txt.',stats:{attacks_detected:2,attacks_blocked:0,active_threats:2}}},
        {type:'defense',data:{timestamp:new Date().toISOString(),action:'IP BLOCKED',blocked_ip:'45.142.212.100',service_protected:'AUTH SERVER',ai_analysis:'Firewall rule deployed — attacker IP blacklisted at kernel level.',stats:{attacks_detected:2,attacks_blocked:1,active_threats:1}}},
        {type:'attack',data:{timestamp:new Date().toISOString(),attack_type:'SQL_INJECTION',source_ip:'78.47.139.201',target_service:'DATABASE',severity:'CRITICAL',payload:"' OR 1=1-- UNION SELECT * FROM users--",ai_analysis:'SQL injection payload attempting credential extraction from database.',stats:{attacks_detected:3,attacks_blocked:1,active_threats:2}}},
      ]
      let d = 0
      for (const ev of events) { setTimeout(() => handleMessage(ev), d); d += 2500 }
    }
    setTimeout(() => setSimRunning(false), 18000)
  }

  async function engageHoneypot() {
    setHoneypotActive(true)
    try {
      await fetch(`${API_BASE}/honeypot/engage`, { method:'POST' })
    } catch {
      const tools = ['Nmap','SQLMap','Hydra','Gobuster']
      const payloads = ['nmap -sV scan results','\'OR 1=1--','admin:password123','../../../etc/passwd']
      const srcIp = '192.168.1.200'
      tools.forEach((tool, i) => {
        setTimeout(() => {
          handleMessage({type:'honeypot',data:{
            timestamp:new Date().toISOString(),source_ip:srcIp,
            service:['WEB_LOGIN','DATABASE','API_USERS','DIR_TRAVERSAL'][i],
            payload:payloads[i],tool_detected:tool,
            intel_update:{ip:srcIp,tools:tools.slice(0,i+1),threat_score:(i+1)*22,
              command:payloads[i],services_hit:['WEB_LOGIN','DATABASE','API_USERS','DIR_TRAVERSAL'].slice(0,i+1)}}})
        }, i * 2200)
      })
      // Demo retaliation
      setTimeout(() => {
        [{phase:'TRACE',message:`SENTINEL COUNTERATTACK INITIATED — Tracing route to ${srcIp}`},
         {phase:'TRACE_COMPLETE',message:'Network path mapped — 3 hops to attacker machine',hops:[`1  ${srcIp}  1.2ms  1.1ms`,'2  192.168.1.1  2.4ms','3  attacker.local']},
         {phase:'SCAN',message:`Scanning attacker machine ${srcIp} — exposing attack surface...`},
         {phase:'SCAN_COMPLETE',message:'Attacker machine scanned — 2 exposed ports found',os_detected:'Linux Kali 2024.1 (x86_64)',open_ports:['22/tcp  open  ssh','4444/tcp  open  krb524']},
         {phase:'DOSSIER',message:'AI generating attacker threat dossier...'},
         {phase:'EXPOSED',message:'ATTACKER FULLY EXPOSED — COUNTERATTACK COMPLETE',attacker_ip:srcIp,
          os_detected:'Linux Kali 2024.1',mac_address:'AA:BB:CC:DD:EE:FF',
          open_ports:['22/tcp open ssh','4444/tcp open krb524'],
          dossier:`Threat actor at ${srcIp} identified as a skilled attacker using a full Kali Linux toolkit including Nmap, SQLMap, and Hydra. Systematic recon-then-exploit pattern indicates automated attack toolchain with manual oversight. Machine exposes port 4444 suggesting active Metasploit listener — likely a seasoned penetration tester or malicious actor operating from a local network position.`,
          threat_score:88,tools:['Nmap','SQLMap','Hydra','Gobuster'],services_hit:['WEB_LOGIN','DATABASE','API_USERS','DIR_TRAVERSAL']}
        ].forEach((step, i) => {
          setTimeout(() => handleMessage({type:'retaliation',data:{...step,timestamp:new Date().toISOString()}}), i * 2500 + 6000)
        })
      }, 8000)
    }
  }

  const isRetaliationMode = retaliationActive || retaliationSteps.some(s => s.phase === 'EXPOSED')
  const timeStr = now.toLocaleTimeString('en-US', { hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit' })
  const dateStr = now.toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' })

  return (
    <div className={`sentinel-root${isRetaliationMode ? ' retaliation-mode' : ''}`}>
      <div className="scanlines" />

      <header className="sentinel-header">
        <div className="sentinel-logo">
          SENTIN<span className="e-letter">E</span>L
          <span style={{fontSize:9,marginLeft:10,letterSpacing:2,color:'var(--gray)',fontWeight:400}}>THREAT INTELLIGENCE</span>
        </div>
        <div className="header-center">
          <span>
            <span className={`status-dot ${wsStatus==='online' ? 'online' : 'offline'}`} />
            {wsStatus==='online' ? 'LIVE' : wsStatus==='reconnecting' ? 'RECONNECTING' : 'DEMO MODE'}
          </span>
          <span style={{color:'var(--border2)'}}>|</span>
          <span>MONITOR: <span className="conn-ok">ACTIVE</span></span>
          <span style={{color:'var(--border2)'}}>|</span>
          {retaliationActive && <span style={{color:'var(--purple)',animation:'blink .5s infinite'}}>⚡ COUNTERATTACK ACTIVE</span>}
          {!retaliationActive && <span>PACKETS: <span style={{color:'var(--cyan)'}}>{(stats.attacks_detected * 4231 + 18422).toLocaleString()}</span></span>}
        </div>
        <div className="header-time">{timeStr} <span style={{color:'var(--gray)',marginLeft:6}}>{dateStr}</span></div>
      </header>

      <main className="sentinel-main">
        {/* LEFT: Threat Feed */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">⚡ Live Threat Feed</span>
            <span style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--red)'}}>
              {feedEntries.filter(e=>e.entryType==='attack').length} events
            </span>
          </div>
          <ThreatFeed entries={feedEntries} />
        </div>

        {/* CENTER: Network + Controls */}
        <div className="panel" style={{borderRight:'1px solid var(--border2)'}}>
          <div className="panel-header">
            <span className="panel-title">🌐 Network Status</span>
            <span style={{fontFamily:'var(--font-hud)',fontSize:9,letterSpacing:2,
              color: retaliationActive ? 'var(--purple)' : underAttack ? 'var(--red)' : 'var(--green)',
              animation:(underAttack||retaliationActive) ? 'blink .5s infinite' : 'none'}}>
              {retaliationActive ? '⚡ RETALIATING' : underAttack ? '⚠ UNDER ATTACK' : '● SECURE'}
            </span>
          </div>

          <div className="stats-row">
            <div className="stat-box"><div className="stat-label">Detected</div><div className="stat-value detected">{stats.attacks_detected}</div></div>
            <div className="stat-box"><div className="stat-label">Blocked</div><div className="stat-value blocked">{stats.attacks_blocked}</div></div>
            <div className="stat-box"><div className="stat-label">Active</div><div className="stat-value active">{stats.active_threats}</div></div>
          </div>

          <div className="panel-body" style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',overflow:'visible'}}>
            <Radar underAttack={underAttack} retaliationActive={retaliationActive} />

            <div className="nodes-container" style={{width:'100%'}}>
              <NetworkNode icon="🗄" label="DATABASE"    status={nodeStates.DATABASE} />
              <NetworkNode icon="⚙" label="API SERVER"  status={nodeStates['API SERVER']} />
              <NetworkNode icon="🔐" label="AUTH SERVER" status={nodeStates['AUTH SERVER']} />
            </div>

            {retaliationActive && (
              <div className="retaliation-bar" style={{width:'calc(100% - 32px)'}}>
                <div className="retaliation-bar-dot" />
                <div className="retaliation-bar-text">
                  {retaliationSteps[retaliationSteps.length-1]?.message?.slice(0,60) || 'COUNTERATTACK IN PROGRESS...'}
                </div>
              </div>
            )}

            <div className="btn-row" style={{width:'100%'}}>
              <button className="btn-attack" onClick={simulateAttack} disabled={simRunning}>
                {simRunning ? '⚡ ATTACK IN PROGRESS...' : '⚡ SIMULATE ATTACK'}
              </button>
              {attackDetected && !honeypotActive && (
                <button className="btn-honeypot" onClick={engageHoneypot}>
                  🍯 ENGAGE HONEYPOT
                </button>
              )}
              {honeypotActive && (
                <div className="honeypot-active-banner">
                  🍯 HONEYPOT ACTIVE — ATTACKER TRAPPED
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT: Attacker Profile / Retaliation */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title" style={{color: retaliationActive ? 'var(--purple)' : isRetaliationMode ? 'var(--red)' : 'var(--cyan)'}}>
              {retaliationActive ? '⚡ Counterattack' : isRetaliationMode ? '🎯 Attacker Exposed' : '🎯 Attacker Profile'}
            </span>
            {profile?.threat_score > 0 && (
              <span style={{fontFamily:'var(--font-hud)',fontSize:9,color:'var(--red)',letterSpacing:1}}>
                THREAT: {profile.threat_score}/100
              </span>
            )}
          </div>
          <AttackerPanel
            profile={profile}
            honeypotEvents={honeypotEvents}
            retaliationSteps={retaliationSteps}
            retaliationActive={retaliationActive}
          />
        </div>
      </main>

      <div className="conn-bar">
        <span>WS: <span className={wsStatus==='online' ? 'conn-ok' : 'conn-err'}>
          {wsStatus==='online' ? `${WS_URL} ✓` : wsStatus.toUpperCase()}
        </span></span>
        <span>|</span>
        <span>API: <span className="conn-warn">{API_BASE}</span></span>
        <span>|</span>
        <span>BLOCKED IPs: <span style={{color:'var(--red)'}}>{stats.attacks_blocked}</span></span>
        <span>|</span>
        {retaliationActive
          ? <span style={{color:'var(--purple)',animation:'blink .5s infinite'}}>⚡ COUNTERATTACK RUNNING</span>
          : <span>MODE: <span className="conn-ok">{wsStatus==='online' ? 'LIVE' : 'DEMO'}</span></span>}
        <span style={{marginLeft:'auto',color:'var(--gray)',fontSize:8}}>SENTINEL v2.0 — HACKATHON DEMO BUILD</span>
      </div>
    </div>
  )
}
