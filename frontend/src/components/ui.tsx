export function PageTitle({ eyebrow, title, subtitle }: { eyebrow: string; title: string; subtitle: string }) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="subtitle">{subtitle}</p></div></div>
}

export function Empty({ title, text, action, onAction }: { title: string; text: string; action?: string; onAction?: () => void }) {
  return <div className="empty-state" role="status"><svg className="empty-state-icon" width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true" focusable="false"><rect x="4.5" y="5.5" width="19" height="17" rx="4" stroke="currentColor" /><path d="M9 11h10M9 15h6" stroke="currentColor" strokeLinecap="round" /><circle cx="21.5" cy="21" r="4" fill="var(--surface-inset)" stroke="currentColor" /><path d="M21.5 19.5v3M20 21h3" stroke="currentColor" strokeLinecap="round" /></svg><strong>{title}</strong><p>{text}</p>{action && onAction && <button className="small-button" onClick={onAction}>{action}</button>}</div>
}

export function StatusBadge({ value }: { value: string }) {
  return <span className={`status-badge ${value.toLowerCase().replaceAll(' ', '_')}`} role="status">{value.replaceAll('_', ' ')}</span>
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) { return <div className="loading-state" role="status" aria-live="polite">{label}</div> }
export function ErrorState({ message }: { message: string }) { return <div className="alert error" role="alert">{message}</div> }
