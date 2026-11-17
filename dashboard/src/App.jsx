import React, { useEffect, useState } from 'react'
import './index.css'

// The agent's Server-Sent Events endpoint. Each message is one alert as JSON (see docs/API.md).
const streamURL = import.meta.env.VITE_EVENTS_URL || 'http://localhost:8090/events'

export default function App() {
  const [alerts, setAlerts] = useState([])
  const [status, setStatus] = useState('disconnected')

  useEffect(() => {
    const es = new EventSource(streamURL)
    es.onopen = () => setStatus('connected')
    es.onerror = () => setStatus('error')
    es.onmessage = (msg) => {
      try {
        const alert = JSON.parse(msg.data)
        setAlerts((cur) => [alert, ...cur].slice(0, 200))
      } catch (e) {
        console.warn('bad alert', e)
      }
    }
    return () => es.close()
  }, [])

  return (
    <div className="page">
      <header>
        <div>
          <h1>Runtime Security Monitor</h1>
          <p>Alerts from the eBPF agent, newest first (educational demo)</p>
        </div>
        <span className={`pill ${status}`}>Stream: {status}</span>
      </header>

      <section className="grid">
        <Card title="Live Alerts" full>
          <LiveTable alerts={alerts} />
        </Card>
        <Card title="Alerts by Container">
          <Heatmap alerts={alerts} />
        </Card>
        <Card title="Alerts by Rule">
          <RuleCounts alerts={alerts} />
        </Card>
        <Card title="Watched-Port Connections">
          <ReverseShell alerts={alerts} />
        </Card>
        <Card title="Injection Primitives">
          <Injection alerts={alerts} />
        </Card>
      </section>
    </div>
  )
}

function Card({ title, children, full }) {
  return (
    <div className={`card ${full ? 'full' : ''}`}>
      <h3>{title}</h3>
      {children}
    </div>
  )
}

function destination(event) {
  if (!event?.dst_ip) return ''
  return `${event.dst_ip}:${event.dst_port}`
}

function containerLabel(event) {
  const id = event?.container?.id
  return !id || id === 'host' ? 'host' : id.slice(0, 12)
}

function LiveTable({ alerts }) {
  if (alerts.length === 0) return <p className="muted">Waiting for alerts…</p>
  return (
    <table className="events">
      <thead>
        <tr>
          <th>Time</th>
          <th>Rule</th>
          <th>PID</th>
          <th>Process</th>
          <th>Path / destination</th>
          <th>Container</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((a, idx) => (
          <tr key={idx}>
            <td>{a.event?.timestamp ? new Date(a.event.timestamp).toLocaleTimeString() : ''}</td>
            <td>{a.rule_id}</td>
            <td>{a.event?.pid}</td>
            <td>{a.event?.comm}</td>
            <td>{destination(a.event) || a.event?.filename || ''}</td>
            <td>{containerLabel(a.event)}</td>
            <td>{a.reason}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

// Counts the alerts held in the browser (the newest 200) per container.
function Heatmap({ alerts }) {
  const buckets = {}
  alerts.forEach((a) => {
    const key = containerLabel(a.event)
    buckets[key] = (buckets[key] || 0) + 1
  })
  const entries = Object.entries(buckets)
  if (entries.length === 0) return <p className="muted">No data</p>
  return (
    <div className="heatmap">
      {entries.map(([key, count]) => (
        <div key={key} className="heat" style={{ opacity: Math.min(1, 0.3 + count / 10) }}>
          <span>{key}</span>
          <strong>{count}</strong>
        </div>
      ))}
    </div>
  )
}

// Counts the alerts held in the browser per rule, as a share of the largest count.
function RuleCounts({ alerts }) {
  const counts = {}
  alerts.forEach((a) => {
    counts[a.rule_id] = (counts[a.rule_id] || 0) + 1
  })
  const entries = Object.entries(counts).sort((x, y) => y[1] - x[1])
  if (entries.length === 0) return <p className="muted">No data</p>
  const max = entries[0][1]
  return (
    <div>
      {entries.map(([rule, count]) => (
        <div key={rule} className="bar">
          <span>{rule}</span>
          <div className="bar-meter">
            <div className="bar-fill" style={{ width: `${(count / max) * 100}%`, background: '#3b82f6' }} />
          </div>
          <span className="muted">{count}</span>
        </div>
      ))}
    </div>
  )
}

function ReverseShell({ alerts }) {
  const hits = alerts.filter((a) => a.rule_id === 'reverse_shell')
  if (hits.length === 0) return <p className="muted">None seen</p>
  return hits.slice(0, 5).map((a, idx) => (
    <div key={idx} className="pill high">{a.event?.comm} → {destination(a.event)}</div>
  ))
}

function Injection({ alerts }) {
  const hits = alerts.filter((a) => a.rule_id === 'process_injection')
  if (hits.length === 0) return <p className="muted">None seen</p>
  return hits.slice(0, 5).map((a, idx) => (
    <div key={idx} className="pill warning">{a.event?.comm}: {a.reason}</div>
  ))
}
