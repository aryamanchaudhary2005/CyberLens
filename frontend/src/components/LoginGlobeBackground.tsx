import { useEffect, useRef, useState } from 'react'
import { useDecorativeMotion, useMotionConstraints } from './motion'

type LoginGlobeBackgroundProps = { reducedMotion: boolean; paused: boolean; onPausedChange: (paused: boolean) => void; onEnableMotion: () => void }

/** Original decorative vector art; it is not an attack map or telemetry view. */
export function LoginGlobeBackground({ reducedMotion, paused, onPausedChange, onEnableMotion }: LoginGlobeBackgroundProps) {
  const globe = useRef<HTMLImageElement>(null)
  const saveData = useMotionConstraints(false)
  const [assetFailed, setAssetFailed] = useState(false)
  const canvas = useRef<HTMLCanvasElement>(null)
  const renderer = useRef<ReturnType<typeof import('./digital-earth').createDigitalEarth> | null>(null)
  const [rendererReady, setRendererReady] = useState(false)
  const [rendererFailed, setRendererFailed] = useState(false)
  const { running } = useDecorativeMotion(globe, reducedMotion, paused)
  const runningRef = useRef(running)
  runningRef.current = running
  const canRender = !reducedMotion && !saveData && !assetFailed && !rendererFailed

  useEffect(() => {
    if (!canRender || !canvas.current) return
    const target = canvas.current
    let cancelled = false
    const fail = () => { renderer.current?.dispose(); renderer.current = null; setRendererReady(false); setRendererFailed(true) }
    target.addEventListener('contextlost', fail)
    // Download the renderer only when motion is permitted. Login never waits.
    void import('./digital-earth').then(({ createDigitalEarth }) => {
      if (cancelled) return
      renderer.current = createDigitalEarth(target)
      renderer.current.setRunning(runningRef.current)
      setRendererReady(true)
    }).catch(() => { if (!cancelled) fail() })
    return () => {
      cancelled = true; renderer.current?.dispose(); renderer.current = null
      target.removeEventListener('contextlost', fail)
      setRendererReady(false)
    }
  }, [canRender])

  useEffect(() => { renderer.current?.setRunning(running) }, [running])

  const staticOnly = reducedMotion || saveData || assetFailed || rendererFailed
  const animationRunning = !staticOnly && running
  const state = staticOnly ? 'static' : animationRunning ? 'running' : 'paused'

  return <>
    <div className="login-globe-art" aria-hidden="true" data-state={state} data-renderer={rendererReady ? 'canvas' : 'static'}>
      {!assetFailed
        ? <img ref={globe} className="login-globe-object" src="/login-globe.svg" alt="" decoding="async" draggable={false} onError={() => setAssetFailed(true)} />
        : <StaticGlobeFallback />}
      {canRender && <canvas ref={canvas} className="login-globe-canvas" />}
    </div>
    <button
      className="login-globe-toggle"
      type="button"
      aria-label={reducedMotion && !saveData && !assetFailed && !rendererFailed ? 'Enable decorative motion' : staticOnly ? `Globe motion disabled${saveData ? ' by data-saving preference' : ''}` : paused ? 'Resume decorative globe motion' : 'Pause decorative globe motion'}
      disabled={saveData || assetFailed || rendererFailed}
      onClick={() => { if (reducedMotion) onEnableMotion(); else onPausedChange(!paused) }}
      title={reducedMotion ? 'Reduced motion is enabled. Choose to animate decorative backgrounds and lettering for this tab.' : saveData ? 'Data saver keeps decorative effects static.' : rendererFailed || assetFailed ? 'The globe renderer is unavailable; the login remains usable.' : 'Decorative Earth and connections; not live security activity.'}
    >
      {reducedMotion && !saveData && !assetFailed && !rendererFailed ? 'Reduced motion · Enable effects' : saveData ? 'Data saver · Static globe' : staticOnly ? 'Globe unavailable' : paused ? 'Resume motion' : 'Pause motion'}
    </button>
  </>
}

function StaticGlobeFallback() {
  return <svg className="login-globe-object login-globe-fallback" viewBox="0 0 640 640" focusable="false">
    <defs>
      <radialGradient id="login-globe-fallback-ocean" cx="35%" cy="28%" r="76%"><stop stopColor="#1b2a50"/><stop offset=".62" stopColor="#111a30"/><stop offset="1" stopColor="#090e19"/></radialGradient>
      <clipPath id="login-globe-fallback-clip"><circle cx="320" cy="320" r="224"/></clipPath>
    </defs>
    <circle cx="320" cy="320" r="282" fill="#6d5df6" opacity=".12"/>
    <circle cx="320" cy="320" r="224" fill="url(#login-globe-fallback-ocean)" stroke="#8790ff" strokeOpacity=".57" strokeWidth="2"/>
    <g clipPath="url(#login-globe-fallback-clip)" fill="#7d78ff" fillOpacity=".42" stroke="#aaa4ff" strokeOpacity=".42" strokeWidth="2">
      <path d="m157 180 20-20 29-7 15 12 22 3 17 15-5 17-17 10-4 18-19 11-5 21-17 7-8-18-17-8-7-18-14-6-8-18 8-19Z"/>
      <path d="m229 260 22-6 20 13 8 19-8 23-10 18-4 28-13 25-11-17-4-27-12-22-3-27 15-27Z"/>
      <path d="m323 222 21-11 24 4 16 17-2 19-13 9-6 21-13 13-12 26-14 15-13-15-3-24-13-21 2-23 10-17-4-13 13-13Z"/>
      <path d="m355 179 23-11 26 6 13-7 27 12 18 18-11 14-25-2-10 14-23-7-14 12-17-11-15 5-13-16 9-13-8-14Z"/>
      <path d="m431 354 21-8 19 9 9 17-14 11-23-4-16-12 4-13Z"/>
    </g>
    <g fill="none" stroke="#91a2ff" strokeOpacity=".17">
      <ellipse cx="320" cy="320" rx="82" ry="224"/><ellipse cx="320" cy="320" rx="158" ry="224"/>
      <ellipse cx="320" cy="260" rx="218" ry="39"/><ellipse cx="320" cy="320" rx="222" ry="78"/><ellipse cx="320" cy="380" rx="218" ry="39"/>
    </g>
    <circle cx="320" cy="320" r="224" fill="none" stroke="#afb0ff" strokeOpacity=".45" strokeWidth="1.2"/>
  </svg>
}
