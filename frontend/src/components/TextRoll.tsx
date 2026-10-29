import type { CSSProperties } from 'react'

export function TextRoll({ text = 'CyberLens', animate = true, replayToken = 0, decorative = false }: {
  text?: string
  animate?: boolean
  replayToken?: string | number
  decorative?: boolean
}) {
  return <span className={`text-roll${animate ? '' : ' text-roll-static'}`} role={decorative ? undefined : 'img'} aria-label={decorative ? undefined : text} aria-hidden={decorative || undefined}>
    <span className="text-roll-visual" key={replayToken} aria-hidden="true">{Array.from(text).map((character, index) => <span className="text-roll-cell" key={`${index}-${character}`} style={{ '--roll-delay': `${index * 16}ms` } as CSSProperties}><span className="text-roll-base">{character}</span>{animate && <span className="text-roll-motion">{character}</span>}</span>)}</span>
  </span>
}
