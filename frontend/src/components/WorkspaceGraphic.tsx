import { useId } from 'react'
import { useInitialMotion } from './motion'

/** A static illustration of the existing review workflow, not live telemetry. */
export function WorkspaceGraphic() {
  const id = useId().replaceAll(':', '')
  return <div className="workspace-graphic" aria-hidden="true">
    <svg viewBox="0 0 500 290" fill="none" focusable="false">
      <defs><linearGradient id={`${id}-line`} x1="58" y1="70" x2="432" y2="250" gradientUnits="userSpaceOnUse"><stop stopColor="#86a9ff" /><stop offset="1" stopColor="#9c8cff" /></linearGradient></defs>
      <rect x="47" y="25" width="406" height="235" rx="16" className="graphic-window" />
      <path d="M47 62h406" className="graphic-divider" />
      <circle cx="66" cy="44" r="3" fill="#7588ad" /><circle cx="78" cy="44" r="3" fill="#52617e" /><circle cx="90" cy="44" r="3" fill="#3b4860" />
      <path d="M140 127h74c22 0 20 52 43 52h93M140 208h51c22 0 24-29 48-29" stroke={`url(#${id}-line)`} strokeWidth="2" />
      <circle cx="239" cy="179" r="42" className="graphic-orbit" /><circle cx="239" cy="179" r="32" className="graphic-core" />
      <path d="m239 160 16 7v12c0 11-8 17-16 21-8-4-16-10-16-21v-12l16-7Z" stroke="#adc1ff" strokeWidth="1.7" /><path d="m232 179 5 5 10-11" stroke="#adc1ff" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="22" y="92" width="131" height="58" rx="10" className="graphic-tile" /><rect x="35" y="105" width="28" height="28" rx="7" className="graphic-icon" /><path d="m49 111 8 4-8 4-8-4 8-4Zm-8 9 8 4 8-4" stroke="#9cb9ff" strokeWidth="1.5" strokeLinejoin="round" /><text x="73" y="115">ASSETS</text><path d="M73 126h58" className="graphic-text-line" />
      <rect x="48" y="182" width="117" height="58" rx="10" className="graphic-tile" /><rect x="61" y="195" width="28" height="28" rx="7" className="graphic-icon violet" /><path d="M70 200h8l3 3v15H69v-18Z" stroke="#c2b4ff" strokeWidth="1.4" /><path d="M72 207h6m-6 4h6" stroke="#c2b4ff" strokeWidth="1.4" /><text x="99" y="205">EVIDENCE</text><path d="M99 216h48" className="graphic-text-line" />
      <rect x="336" y="143" width="141" height="72" rx="11" className="graphic-tile" /><rect x="350" y="157" width="28" height="28" rx="7" className="graphic-icon" /><path d="m357 171 4 4 9-9" stroke="#9cb9ff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /><text x="389" y="167">ANALYST REVIEW</text><path d="M389 179h65M350 199h103" className="graphic-text-line" />
    </svg>
    <span>Source evidence → analyst review → explainable decisions</span>
  </div>
}

export function ScoreRing({ value, band }: { value: number | null; band: string | null }) {
  const animate = useInitialMotion(440)
  const circumference = 2 * Math.PI * 43
  const safeValue = value == null ? 0 : Math.max(0, Math.min(100, value))
  return <svg className={`score-ring ${band ?? 'unknown'}${animate && value != null ? ' score-ring-enter' : ''}`} viewBox="0 0 110 110" fill="none" aria-hidden="true" focusable="false" data-score-motion={animate && value != null ? 'initial' : 'static'}>
    <circle cx="55" cy="55" r="43" className="score-ring-track" />
    {value != null && <circle cx="55" cy="55" r="43" className="score-ring-value" strokeDasharray={`${circumference * safeValue / 100} ${circumference}`} transform="rotate(-90 55 55)" />}
    <path d="m55 37 14 6v11c0 10-7 15-14 19-7-4-14-9-14-19V43l14-6Z" className="score-ring-shield" /><path d="M55 48v10m0 5v1" className="score-ring-shield" />
  </svg>
}
