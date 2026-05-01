import { useState, useEffect, useRef, useCallback } from 'react'

const WS_URL   = 'ws://localhost:8000/ws'
const API_BASE = 'http://localhost:8000'

// ─── Hooks ────────────────────────────────────────────────────
function useSentinelWS(onMessage) {
  const wsRef      = useRef(null)
  const retryRef   = useRef(null)
  const [wsStatus, setWsStatus] = useState('connecting')

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => {
        setWsStatus('online')
        clearTimeout(retryRef.current)
      }
      ws.onmessage = (e) => {
        try { onMessage(JSON.parse(e.data)) } catch {}
      }
      ws.onclose = () => {
        setWsStatus('reconnecting')
        retryRef.current = setTimeout(connect, 3000)
      }
      ws.onerror = () => {
        setWsStatus('error')
        ws.close()
      }
    } catch {
      setWsStatus('error')
      retryRef.current = setTimeout(connect, 3000)
    }
  }, [onMessage])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(retryRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  return wsStatus
}

// ─── Helpers ──────────────────────────────────────────────────
function fmtTime(iso) {
  const d = new Date(iso || Date.now())
  return d.toLocaleTimeString('en-US', { hour12: false })
}

function useNow() {
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

// ─── Threat Feed (Left Panel) ─────────────────────────────────
function ThreatEntry({ entry }) {
  const isDefense = entry.entryType === 'defense'
  return (
    <div className={`threat-entry ${isDefense ? 'defense-entry' : entry.severity || 'MEDIUM'}`}>
      <div className="threat-time">{fmtTime(entry.timestamp)}</div>
      <div className="threat-type">{isDefense ? '🛡 ' : '⚡ '}{entry.attack_type || entry.action || 'EVENT'}</div>
      <div className="threat-meta">
        {entry.source_ip && <span className="threat-ip">{entry.source_ip}</span>}
        {entry.blocked_ip && <span className="threat-ip">{entry.blocked_ip}</span>}
        {entry.target_service && <span>→ {entry.target_service}</span>}
        {entry.service_protected && <span>→ {entry.service_protected}</span>}
        {!isDefense && entry.severity && (
          <span className={`severity-badge ${entry.severity}`}>{entry.severity}</span>
        )}
        {isDefense && <span className="severity-badge DEFENSE">BLOCKED</span>}
      </div>
      {(entry.ai_analysis || entry.message) && (
        <div className="threat-ai">{entry.ai_analysis || entry.message}</div>
      )}
    </div>
  )
}

function ThreatFeed({ entries }) {
  const bottomRef = useRef(null)
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [entries])

  return (
    <div className="panel-body threat-feed">
      {entries.length === 0 ? (
        <div className="feed-empty">
          <div className="feed-empty-icon">📡</div>
          <div>MONITORING NETWORK TRAFFIC</div>
          <div style={{ color: '#3a3a5a', fontSize: 10 }}>Waiting for threat activity...</div>
        </div>
      ) : (
        entries.map((e, i) => <ThreatEntry key={i} entry={e} />)
      )}
      <div ref={bottomRef} />
    </div>
  )
}

// ─── Radar (Center Panel) ─────────────────────────────────────
function Radar({ underAttack }) {
  const speed     = underAttack ? '1.2s' : '3s'
  const color     = underAttack ? 'var(--red)' : 'var(--cyan)'
  const pingDelay = underAttack ? '0s, 0.4s, 0.8s' : '0s, 0.7s'
  const pingSizes = underAttack ? [260, 200, 140] : [240, 160]

  return (
    <div className="radar-container">
      {/* Background rings */}
      {[260, 200, 140, 80].map((d, i) => (
        <div key={i} className="radar-ring" style={{
          width: d, height: d,
          borderColor: `${color}${['22','33','44','55'][i]}`,
          marginLeft: -d/2, marginTop: -d/2,
        }} />
      ))}

      {/* Crosshair */}
      <div className="radar-cross" />

      {/* Sweep line */}
      <div className="radar-sweep" style={{ inset: 0, position: 'absolute', borderRadius: '50%', overflow: 'hidden' }}>
        <div className="radar-sweep-line" style={{
          background: `linear-gradient(90deg, transparent, ${color}cc)`,
          animationDuration: speed,
        }} />
      </div>

      {/* Pings */}
      {pingSizes.map((d, i) => (
        <div key={i} className="radar-ping" style={{
          width: d, height: d,
          marginLeft: -d/2, marginTop: -d/2,
          borderColor: color,
          animationDuration: underAttack ? '1s' : '2s',
          animationDelay: `${i * (underAttack ? 0.33 : 0.7)}s`,
          opacity: underAttack ? 0.8 : 0.4,
        }} />
      ))}

      {/* Center dot */}
      <div style={{
        position: 'absolute', top: '50%', left: '50%',
        width: 8, height: 8, borderRadius: '50%',
        background: color,
        transform: 'translate(-50%,-50%)',
        boxShadow: `0 0 12px ${color}`,
      }} />

      {/* Status text */}
      <div style={{
        position: 'absolute', top: '50%', left: '50%',
        transform: 'translate(-50%, 60px)',
        fontFamily: 'var(--font-hud)',
        fontSize: 10, letterSpacing: 3,
        color: underAttack ? 'var(--red)' : 'var(--cyan)',
        animation: underAttack ? 'blink 0.6s infinite' : 'none',
        textTransform: 'uppercase',
      }}>
        {underAttack ? '⚠ UNDER ATTACK' : '● MONITORING'}
      </div>
    </div>
  )
}

// ─── Network Nodes ────────────────────────────────────────────
function NetworkNode({ icon, label, status }) {
  return (
    <div className="network-node">
      <div className={`node-orb ${status}`}>{icon}</div>
      <div className={`node-label`} style={{
        color: status === 'safe' ? 'var(--green)' : status === 'danger' ? 'var(--red)' : 'var(--amber)'
      }}>{label}</div>
      <div className="node-status">{status.toUpperCase()}</div>
    </div>
  )
}

// ─── Attacker Profile (Right Panel) ──────────────────────────
function TypewriterField({ label, value, delay = 0 }) {
  const [shown, setShown] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setShown(true), delay)
    return () => clearTimeout(t)
  }, [delay])

  return shown ? (
    <div className="profile-field">
      <div className="profile-field-label">{label}</div>
      <div className="profile-field-value done" style={{ color: 'var(--cyan)', whiteSpace: 'normal', borderRight: 'none', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        {value}
      </div>
    </div>
  ) : null
}

function ThreatScoreGauge({ score }) {
  const color = score >= 75 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : 'var(--green)'
  return (
    <div className="threat-score-container">
      <div className="threat-score-label">
        <span>THREAT SCORE</span>
        <span style={{ color, fontFamily: 'var(--font-hud)', fontSize: 14, fontWeight: 900 }}>{score}/100</span>
      </div>
      <div className="threat-score-bar-bg">
        <div className="threat-score-bar-fill" style={{
          width: `${score}%`,
          background: `linear-gradient(90deg, var(--green-dim), ${color})`,
          boxShadow: `0 0 10px ${color}`,
        }} />
      </div>
    </div>
  )
}

function AttackerProfile({ profile, honeypotEvents }) {
  const hasData = profile && profile.ip

  if (!hasData) {
    return (
      <div className="panel-body">
        <div className="profile-empty">
          <div className="profile-empty-icon">🎯</div>
          <div className="profile-empty-text">
            AWAITING<br />THREAT<br />INTELLIGENCE
          </div>
          <div style={{ fontSize: 9, letterSpacing: 2, color: '#3a3a5a', fontFamily: 'var(--font-mono)' }}>
            ENGAGE HONEYPOT TO BEGIN PROFILING
          </div>
        </div>
      </div>
    )
  }

  const score     = profile.threat_score || 0
  const tools     = Array.from(new Set(profile.tools || []))
  const commands  = profile.commands || []
  const services  = profile.services_hit || []

  return (
    <div className="panel-body" style={{ overflow: 'auto' }}>
      {score >= 50 && (
        <div className="profile-exposed">⚠ ATTACKER EXPOSED</div>
      )}

      <ThreatScoreGauge score={score} />
      <div className="divider" />

      <TypewriterField label="ATTACKER IP"         value={profile.ip}                   delay={100} />
      <TypewriterField label="OS FINGERPRINT"      value={profile.os || 'Linux / Kali 2024'}    delay={400} />
      <TypewriterField label="MACHINE ID"          value={profile.machine_id || `HOSTILE-${profile.ip?.replace(/\./g,'-')}`} delay={700} />
      <TypewriterField label="BEHAVIOR PATTERN"    value={profile.behavior || 'Systematic enumeration → brute force → exploitation'} delay={1000} />

      {tools.length > 0 && (
        <div className="profile-field" style={{ animationDelay: '1.3s' }}>
          <div className="profile-field-label">ATTACK TOOLS DETECTED</div>
          <div style={{ marginTop: 4 }}>
            {tools.map((t, i) => <span key={i} className="tool-badge">{t}</span>)}
          </div>
        </div>
      )}

      {services.length > 0 && (
        <TypewriterField label="SERVICES ATTACKED" value={services.join(' → ')} delay={1600} />
      )}

      {commands.length > 0 && (
        <div className="profile-field">
          <div className="profile-field-label">COMMANDS / PAYLOADS CAPTURED</div>
          <div style={{ marginTop: 4, maxHeight: 140, overflowY: 'auto' }}>
            {commands.slice(-8).map((cmd, i) => (
              <div key={i} className="command-entry">
                <span className="command-prompt">$</span>{cmd}
              </div>
            ))}
          </div>
        </div>
      )}

      {honeypotEvents.slice(-3).map((ev, i) => (
        <div key={i} className="hp-ticker">
          <span className="hp-ticker-tag">INTEL</span>
          <span className="hp-ticker-text">
            {ev.service} — {ev.tool_detected || 'probe'} — {ev.payload?.slice(0, 60) || '...'}
          </span>
        </div>
      ))}
    </div>
  )
}

// ─── Main App ─────────────────────────────────────────────────
export default function App() {
  const now   = useNow()
  const [feedEntries,    setFeedEntries]    = useState([])
  const [stats,          setStats]          = useState({ attacks_detected: 0, attacks_blocked: 0, active_threats: 0 })
  const [nodeStates,     setNodeStates]     = useState({ DATABASE: 'safe', 'API SERVER': 'safe', 'AUTH SERVER': 'safe' })
  const [underAttack,    setUnderAttack]    = useState(false)
  const [attackDetected, setAttackDetected] = useState(false)
  const [honeypotActive, setHoneypotActive] = useState(false)
  const [profile,        setProfile]        = useState(null)
  const [honeypotEvents, setHoneypotEvents] = useState([])
  const [simRunning,     setSimRunning]     = useState(false)
  const clearAttackRef = useRef(null)

  const handleMessage = useCallback((msg) => {
    const { type, data } = msg

    if (type === 'init') {
      setStats(data.stats || stats)
      setHoneypotActive(data.honeypot_active || false)
      return
    }

    if (type === 'attack') {
      setStats(data.stats || {})
      setAttackDetected(true)
      setUnderAttack(true)
      clearTimeout(clearAttackRef.current)
      clearAttackRef.current = setTimeout(() => setUnderAttack(false), 6000)

      // Update node states
      const svc = (data.target_service || '').toUpperCase()
      setNodeStates(prev => {
        const next = { ...prev }
        if (svc.includes('DATABASE'))    next['DATABASE']    = 'danger'
        if (svc.includes('API'))         next['API SERVER']  = 'danger'
        if (svc.includes('AUTH'))        next['AUTH SERVER'] = 'danger'
        if (svc.includes('ALL'))         { next['DATABASE'] = 'danger'; next['API SERVER'] = 'danger'; next['AUTH SERVER'] = 'danger' }
        return next
      })

      setFeedEntries(prev => [{ ...data, entryType: 'attack' }, ...prev].slice(0, 80))
    }

    if (type === 'defense') {
      setStats(data.stats || {})
      setUnderAttack(false)

      const svc = (data.service_protected || '').toUpperCase()
      setNodeStates(prev => {
        const next = { ...prev }
        if (svc.includes('DATABASE'))    next['DATABASE']    = 'defended'
        if (svc.includes('API'))         next['API SERVER']  = 'defended'
        if (svc.includes('AUTH'))        next['AUTH SERVER'] = 'defended'
        if (svc.includes('ALL') || data.action?.includes('HONEYPOT')) {
          next['DATABASE'] = 'defended'; next['API SERVER'] = 'defended'; next['AUTH SERVER'] = 'defended'
        }
        return next
      })

      setTimeout(() => {
        setNodeStates(prev => {
          const next = { ...prev }
          Object.keys(next).forEach(k => { if (next[k] === 'defended') next[k] = 'safe' })
          return next
        })
      }, 8000)

      setFeedEntries(prev => [{ ...data, entryType: 'defense' }, ...prev].slice(0, 80))
    }

    if (type === 'honeypot') {
      setHoneypotEvents(prev => [...prev, data].slice(-20))
      const intel = data.intel_update || {}
      setProfile(prev => {
        const tools = new Set([...(prev?.tools || []), ...(intel.tools || []), data.tool_detected].filter(Boolean))
        const commands = [...(prev?.commands || []), intel.command].filter(Boolean).slice(-20)
        const services = [...new Set([...(prev?.services_hit || []), ...(intel.services_hit || []), data.service].filter(Boolean))]
        return {
          ...prev,
          ip:           intel.ip || prev?.ip,
          threat_score: intel.threat_score || prev?.threat_score || 0,
          tools:        [...tools],
          commands,
          services_hit: services,
        }
      })
    }
  }, [])

  const wsStatus = useSentinelWS(handleMessage)

  async function simulateAttack() {
    if (simRunning) return
    setSimRunning(true)
    try {
      await fetch(`${API_BASE}/simulate`, { method: 'POST' })
    } catch {
      // Backend not running — inject demo events locally
      const demoEvents = [
        { type: 'attack', data: { timestamp: new Date().toISOString(), attack_type: 'PORT_SCAN', source_ip: '185.220.101.47', target_service: 'ALL SERVICES', severity: 'HIGH', ai_analysis: 'Aggressive port scan detected — attacker mapping the entire network.', stats: { attacks_detected: 1, attacks_blocked: 0, active_threats: 1 } } },
        { type: 'attack', data: { timestamp: new Date().toISOString(), attack_type: 'BRUTE_FORCE', source_ip: '45.142.212.100', target_service: 'AUTH SERVER', severity: 'CRITICAL', ai_analysis: 'SSH brute force in progress — 500 attempts per minute from hostile IP.', stats: { attacks_detected: 2, attacks_blocked: 0, active_threats: 2 } } },
        { type: 'defense', data: { timestamp: new Date().toISOString(), action: 'IP BLOCKED', blocked_ip: '45.142.212.100', service_protected: 'AUTH SERVER', ai_analysis: 'Firewall rule deployed — attacker IP banned at kernel level.', stats: { attacks_detected: 2, attacks_blocked: 1, active_threats: 1 } } },
        { type: 'attack', data: { timestamp: new Date().toISOString(), attack_type: 'SQL_INJECTION', source_ip: '78.47.139.201', target_service: 'DATABASE', severity: 'CRITICAL', payload: "' OR 1=1-- UNION SELECT * FROM users--", ai_analysis: 'SQL injection payload detected targeting user credentials table.', stats: { attacks_detected: 3, attacks_blocked: 1, active_threats: 2 } } },
      ]
      let delay = 0
      for (const ev of demoEvents) {
        setTimeout(() => handleMessage(ev), delay)
        delay += 2500
      }
    }
    setTimeout(() => setSimRunning(false), 15000)
  }

  async function engageHoneypot() {
    setHoneypotActive(true)
    try {
      await fetch(`${API_BASE}/honeypot/engage`, { method: 'POST' })
    } catch {
      // Demo mode — inject fake honeypot intel
      const tools = ['Nmap', 'SQLMap', 'Hydra']
      const payloads = ["' OR 1=1--", 'admin / 123456', '../../../etc/passwd', 'GET /admin HTTP/1.1']
      tools.forEach((tool, i) => {
        setTimeout(() => {
          handleMessage({
            type: 'honeypot',
            data: {
              timestamp: new Date().toISOString(),
              source_ip: '192.168.1.200',
              service: ['WEB_LOGIN', 'DATABASE', 'API_DATA'][i] || 'PROBE',
              payload: payloads[i],
              tool_detected: tool,
              intel_update: { ip: '192.168.1.200', tools: tools.slice(0, i+1), threat_score: (i+1)*25, command: payloads[i], services_hit: ['WEB_LOGIN', 'DATABASE', 'API_DATA'].slice(0, i+1) },
            },
          })
        }, i * 2000)
      })
    }
  }

  const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  const dateStr = now.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })

  return (
    <div className="sentinel-root">
      {/* Scanlines overlay */}
      <div className="scanlines" />

      {/* Header */}
      <header className="sentinel-header">
        <div className="sentinel-logo">
          SENTIN<span>E</span>L
          <span style={{ fontSize: 10, marginLeft: 12, letterSpacing: 2, color: 'var(--gray)', fontWeight: 400 }}>
            THREAT INTELLIGENCE
          </span>
        </div>

        <div className="header-status">
          <span>
            <span className={`status-dot ${wsStatus === 'online' ? 'online' : 'offline'}`} />
            {wsStatus === 'online' ? 'BACKEND CONNECTED' : wsStatus === 'reconnecting' ? 'RECONNECTING...' : 'DEMO MODE'}
          </span>
          <span style={{ color: 'var(--border)' }}>|</span>
          <span>NETWORK MONITOR: <span className="conn-ok">ACTIVE</span></span>
          <span style={{ color: 'var(--border)' }}>|</span>
          <span>PACKETS ANALYZED: <span style={{ color: 'var(--cyan)' }}>
            {(stats.attacks_detected * 4231 + 14822).toLocaleString()}
          </span></span>
        </div>

        <div className="header-time">
          {timeStr} <span style={{ color: 'var(--gray)', marginLeft: 8 }}>{dateStr}</span>
        </div>
      </header>

      {/* Main 3-panel layout */}
      <main className="sentinel-main">

        {/* LEFT: Threat Feed */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">⚡ Live Threat Feed</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)' }}>
              {feedEntries.filter(e => e.entryType === 'attack').length} events
            </span>
          </div>
          <ThreatFeed entries={feedEntries} />
        </div>

        {/* CENTER: Network Status */}
        <div className="panel center-panel" style={{ borderRight: '1px solid var(--border)' }}>
          <div className="panel-header">
            <span className="panel-title">🌐 Network Status</span>
            <span style={{ fontFamily: 'var(--font-hud)', fontSize: 9, letterSpacing: 2,
              color: underAttack ? 'var(--red)' : 'var(--green)',
              animation: underAttack ? 'blink 0.5s infinite' : 'none' }}>
              {underAttack ? '⚠ UNDER ATTACK' : '● SECURE'}
            </span>
          </div>

          {/* Stats */}
          <div className="stats-row">
            <div className="stat-box">
              <div className="stat-label">Detected</div>
              <div className="stat-value detected">{stats.attacks_detected}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">Blocked</div>
              <div className="stat-value blocked">{stats.attacks_blocked}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">Active</div>
              <div className="stat-value active">{stats.active_threats}</div>
            </div>
          </div>

          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', overflow: 'visible' }}>
            {/* Radar */}
            <Radar underAttack={underAttack} />

            {/* Network Nodes */}
            <div className="nodes-container" style={{ width: '100%' }}>
              <NetworkNode icon="🗄" label="DATABASE"    status={nodeStates['DATABASE']} />
              <NetworkNode icon="⚙" label="API SERVER"  status={nodeStates['API SERVER']} />
              <NetworkNode icon="🔐" label="AUTH SERVER" status={nodeStates['AUTH SERVER']} />
            </div>

            {/* Buttons */}
            <div className="btn-row" style={{ width: '100%' }}>
              <button
                className="btn-attack"
                onClick={simulateAttack}
                disabled={simRunning}
                id="btn-simulate-attack"
              >
                {simRunning ? '⚡ ATTACK IN PROGRESS...' : '⚡ SIMULATE ATTACK'}
              </button>

              {attackDetected && !honeypotActive && (
                <button
                  className="btn-honeypot"
                  onClick={engageHoneypot}
                  id="btn-engage-honeypot"
                >
                  🍯 ENGAGE HONEYPOT
                </button>
              )}

              {honeypotActive && (
                <div style={{
                  textAlign: 'center',
                  fontFamily: 'var(--font-hud)',
                  fontSize: 11,
                  letterSpacing: 2,
                  color: 'var(--amber)',
                  padding: '10px',
                  border: '1px solid var(--amber)',
                  borderRadius: 4,
                  background: 'rgba(255,170,0,0.05)',
                  animation: 'blink 2s infinite',
                }}>
                  🍯 HONEYPOT ACTIVE — TRAP SET
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT: Attacker Profile */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">🎯 Attacker Profile</span>
            {profile?.threat_score > 0 && (
              <span style={{ fontFamily: 'var(--font-hud)', fontSize: 10, color: 'var(--red)', letterSpacing: 1 }}>
                THREAT: {profile.threat_score}/100
              </span>
            )}
          </div>
          <AttackerProfile profile={profile} honeypotEvents={honeypotEvents} />
        </div>

      </main>

      {/* Connection status bar */}
      <div className="conn-bar">
        <span>
          WS: <span className={wsStatus === 'online' ? 'conn-ok' : 'conn-err'}>
            {wsStatus === 'online' ? 'ws://localhost:8000/ws ✓' : wsStatus.toUpperCase()}
          </span>
        </span>
        <span>|</span>
        <span>API: <span className="conn-warn">http://localhost:8000</span></span>
        <span>|</span>
        <span>MODE: <span className="conn-ok">{wsStatus === 'online' ? 'LIVE' : 'DEMO'}</span></span>
        <span>|</span>
        <span style={{ marginLeft: 'auto', color: 'var(--gray)', fontSize: 9 }}>
          SENTINEL v1.0 — HACKATHON DEMO BUILD
        </span>
      </div>
    </div>
  )
}
