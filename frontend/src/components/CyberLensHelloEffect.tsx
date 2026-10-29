import { useRef, type CSSProperties, type SVGProps } from 'react'
import { useDecorativeMotion } from './motion'
import './cyberlens-hello-effect.css'

type CyberLensHelloEffectProps = Omit<SVGProps<SVGSVGElement>, 'children' | 'ref'> & {
  speed?: number
  reducedMotion?: boolean
  paused?: boolean
  replayToken?: number
  onAnimationComplete?: () => void
}

// Original monoline letter paths. Normalized path lengths let each letter draw
// in writing order instead of dashing the outlines of a filled system font.
const letters = [
  'M139 49C123 26 78 26 56 64C31 108 46 141 81 141C103 141 125 124 142 108',
  'M159 78C146 110 149 133 162 134C176 135 191 108 200 78L182 137C175 160 158 169 146 158',
  'M224 132C233 100 251 40 241 28C230 17 214 51 210 87C206 117 213 139 232 134C254 128 271 94 258 81C245 68 227 97 225 113',
  'M287 112C321 113 344 87 329 78C313 68 288 92 286 113C283 138 312 144 343 117',
  'M356 135L374 78C365 103 375 109 389 94C404 77 415 79 418 91',
  'M435 136C474 114 505 62 499 36C494 15 475 34 470 56L451 128C448 143 475 141 498 136L535 128',
  'M552 112C586 113 609 87 594 78C578 68 553 92 551 113C548 138 577 144 608 117',
  'M622 136L639 79L627 122C649 87 670 72 680 82C693 94 666 124 679 134C691 144 711 121 721 105',
  'M789 84C770 64 733 84 741 101C746 111 777 109 776 122C775 141 735 147 723 131M776 122C796 129 818 117 837 102',
] as const

/** Decorative local lettering; the existing lockup supplies the accessible name. */
export function CyberLensHelloEffect({
  className = '',
  speed = 1,
  reducedMotion = false,
  paused = false,
  replayToken = 0,
  onAnimationComplete,
  style,
  ...props
}: CyberLensHelloEffectProps) {
  const safeSpeed = Number.isFinite(speed) ? Math.min(2, Math.max(0.5, speed)) : 1
  const svg = useRef<SVGSVGElement>(null)
  const { running, staticOnly } = useDecorativeMotion(svg, reducedMotion, paused)
  const duration = `${(3.1 / safeSpeed).toFixed(2)}s`
  const combinedStyle = {
    ...style,
    '--cyberlens-draw-duration': duration,
  } as CSSProperties

  return <svg
    {...props}
    ref={svg}
    className={`cyberlens-hello-effect${staticOnly ? ' is-static' : ''}${className ? ` ${className}` : ''}`}
    viewBox="20 14 840 164"
    preserveAspectRatio="xMidYMid meet"
    style={combinedStyle}
    aria-hidden="true"
    focusable="false"
    data-motion={staticOnly ? 'reduced' : 'full'}
    data-playback={staticOnly ? 'static' : running ? 'running' : 'paused'}
    data-wordmark="CyberLens"
  >
    <title>CyberLens</title>
    <g className="cyberlens-hello-effect__base">{letters.map((d, index) => <path key={index} d={d} />)}</g>
    <g key={replayToken} className="cyberlens-hello-effect__ink">
      {letters.map((d, index) => <path key={index} className="cyberlens-hello-effect__draw" d={d} pathLength="1" style={{ '--glyph-delay': `${(index * .16 / safeSpeed).toFixed(3)}s` } as CSSProperties} />)}
      {letters.map((d, index) => <path key={`glint-${index}`} className="cyberlens-hello-effect__glint" d={d} pathLength="1" style={{ '--glint-delay': `${(index * .2).toFixed(1)}s` } as CSSProperties} />)}
      <path className="cyberlens-hello-effect__flourish" d="M64 159C224 169 393 163 548 155S727 149 805 156" pathLength="1" onAnimationEnd={onAnimationComplete} />
      <circle className="cyberlens-hello-effect__node" cx="817" cy="156" r="4" />
    </g>
  </svg>
}
