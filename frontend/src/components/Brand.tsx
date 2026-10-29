import { useState } from 'react'
import { TextRoll } from './TextRoll'

export function BrandMark({ size = 38, monochrome = false, className = '' }: { size?: number; monochrome?: boolean; className?: string }) {
  return <img className={`brand-icon${className ? ` ${className}` : ''}`} src={monochrome ? '/brand/cyberlens-icon-monochrome.svg' : '/brand/cyberlens-icon.svg'} width={size} height={size} alt="" aria-hidden="true" draggable={false} />
}

export function BrandLockup({
  size = 40,
  subtitle,
  animate = true,
  replayToken = 0,
  replayOnHover = false,
  decorative = false,
  className = '',
}: {
  size?: number
  subtitle?: string
  animate?: boolean
  replayToken?: string | number
  replayOnHover?: boolean
  decorative?: boolean
  className?: string
}) {
  const [hoverReplay, setHoverReplay] = useState(0)
  const effectiveReplayToken = `${replayToken}:${hoverReplay}`
  return <span className={`brand-lockup${className ? ` ${className}` : ''}`} role={decorative ? undefined : 'img'} aria-label={decorative ? undefined : 'CyberLens'} aria-hidden={decorative || undefined} onMouseEnter={replayOnHover ? () => setHoverReplay((value) => value + 1) : undefined}>
    <BrandMark size={size} />
    <span className="brand-word-stack"><TextRoll animate={animate} replayToken={effectiveReplayToken} decorative />{subtitle && <small>{subtitle}</small>}</span>
  </span>
}
