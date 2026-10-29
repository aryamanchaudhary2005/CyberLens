import { useEffect, useRef, useState } from 'react'
import { useDecorativeMotion } from './motion'
import './dashboard-bento-scene.css'

/** Decorative reference artwork, independent of workspace records and requests. */
export function DashboardBentoScene({ reducedMotion, paused }: { reducedMotion: boolean; paused: boolean }) {
  const root = useRef<HTMLDivElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const renderer = useRef<{ setRunning: (running: boolean) => void; dispose: () => void } | null>(null)
  const { staticOnly, running } = useDecorativeMotion(root, reducedMotion, paused)
  const latestRunning = useRef(running)
  latestRunning.current = running
  const [ready, setReady] = useState(false)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    if (staticOnly || failed || !canvas.current) return
    let cancelled = false
    const target = canvas.current
    void import('./dashboard-bento-renderer').then(({ createBentoRenderer }) => {
      if (cancelled) return
      renderer.current = createBentoRenderer(target)
      renderer.current.setRunning(latestRunning.current)
      setReady(true)
    }).catch(() => { if (!cancelled) setFailed(true) })
    const lost = (event: Event) => { event.preventDefault(); setFailed(true) }
    target.addEventListener('contextlost', lost)
    return () => {
      cancelled = true
      renderer.current?.dispose()
      renderer.current = null
      target.removeEventListener('contextlost', lost)
      setReady(false)
    }
  }, [staticOnly, failed])

  useEffect(() => { renderer.current?.setRunning(running) }, [running, ready])

  return <div ref={root} className="dashboard-bento-scene" aria-hidden="true" data-renderer={ready && !staticOnly && !failed ? 'canvas' : 'static'} data-playback={running && !failed ? 'running' : 'paused'}>
    <svg className="dashboard-bento-scene__fallback" viewBox="0 0 900 180" preserveAspectRatio="xMidYMid meet" focusable="false">
      <g fill="none" stroke="currentColor" strokeWidth="1">
        <circle cx="150" cy="90" r="70" /><ellipse cx="150" cy="90" rx="35" ry="70" /><ellipse cx="150" cy="90" rx="70" ry="25" /><ellipse cx="150" cy="90" rx="60" ry="50" />
        {[0, 1, 2, 3].map(i => <path key={i} d={`M450 ${20 + i * 22} l65 33 -65 33 -65 -33 Z`} />)}
      </g>
      <g fill="currentColor">{Array.from({ length: 117 }, (_, i) => <circle key={i} cx={654 + i % 13 * 16} cy={26 + Math.floor(i / 13) * 16} r={1 + Math.sin(i * .7) ** 2 * 2} opacity=".6" />)}</g>
    </svg>
    <canvas ref={canvas} className="dashboard-bento-scene__canvas" />
  </div>
}
