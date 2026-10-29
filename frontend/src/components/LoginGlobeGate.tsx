import { Component, lazy, Suspense, type ReactNode } from 'react'
import './login-globe.css'

const LoginGlobeBackground = lazy(() => import('./LoginGlobeBackground').then((module) => ({ default: module.LoginGlobeBackground })))

type GateProps = { reducedMotion: boolean; paused: boolean; onPausedChange: (paused: boolean) => void; onEnableMotion: () => void }
type BoundaryProps = { children: ReactNode; fallback: ReactNode }
type BoundaryState = { failed: boolean }

/** A chunk failure affects only the decoration; the local SVG stays static behind the login. */
class LoginGlobeErrorBoundary extends Component<BoundaryProps, BoundaryState> {
  state: BoundaryState = { failed: false }

  static getDerivedStateFromError(): BoundaryState {
    return { failed: true }
  }

  render() {
    return this.state.failed ? this.props.fallback : this.props.children
  }
}

function StaticGlobe() {
  return <div className="login-globe-art" aria-hidden="true" data-state="static">
    <img className="login-globe-object login-globe-static" src="/login-globe.svg" alt="" decoding="async" draggable={false} />
  </div>
}

export function LoginGlobeGate({ reducedMotion, paused, onPausedChange, onEnableMotion }: GateProps) {
  return <LoginGlobeErrorBoundary fallback={<StaticGlobe />}>
    <Suspense fallback={<StaticGlobe />}>
      <LoginGlobeBackground reducedMotion={reducedMotion} paused={paused} onPausedChange={onPausedChange} onEnableMotion={onEnableMotion} />
    </Suspense>
  </LoginGlobeErrorBoundary>
}
