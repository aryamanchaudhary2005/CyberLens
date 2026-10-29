import { StatusBadge, PageTitle } from '../components/ui'
import type { CinsArmyStatus, OpenPhishStatus, SpamhausDropStatus } from '../api'

export function IntegrationsScreen({ integrations, isDemo, spamhausDrop, cinsArmy, openPhish, canRefreshSpamhaus, canRefreshCinsArmy, canRefreshOpenPhish, onRefreshSpamhaus, onRefreshCinsArmy, onRefreshOpenPhish }: {
  integrations: Array<Record<string, unknown>>; isDemo: boolean; spamhausDrop: SpamhausDropStatus | null
  cinsArmy: CinsArmyStatus | null; openPhish: OpenPhishStatus | null
  canRefreshSpamhaus: boolean; canRefreshCinsArmy: boolean; canRefreshOpenPhish: boolean
  onRefreshSpamhaus: () => void; onRefreshCinsArmy: () => void; onRefreshOpenPhish: () => void
}) {
  const metadata = spamhausDrop?.metadata ?? {}
  const feeds = metadata.feeds && typeof metadata.feeds === 'object' ? metadata.feeds as Record<string, unknown> : {}
  const attemptPending = ['queued', 'dispatched', 'running'].includes(spamhausDrop?.latest_attempt?.status ?? '')
  const age = spamhausDrop?.snapshot_age_seconds == null ? 'Not available' : `${Math.floor(spamhausDrop.snapshot_age_seconds / 3600)} h ${Math.floor((spamhausDrop.snapshot_age_seconds % 3600) / 60)} m`
  const cinsPending = ['queued', 'dispatched', 'running'].includes(cinsArmy?.latest_attempt?.status ?? '')
  const cinsAge = cinsArmy?.snapshot_age_seconds == null ? 'Not available' : `${Math.floor(cinsArmy.snapshot_age_seconds / 3600)} h ${Math.floor((cinsArmy.snapshot_age_seconds % 3600) / 60)} m`
  const openPhishPending = ['queued', 'dispatched', 'running'].includes(openPhish?.latest_attempt?.status ?? '')
  const openPhishAge = openPhish?.snapshot_age_seconds == null ? 'Not available' : `${Math.floor(openPhish.snapshot_age_seconds / 3600)} h ${Math.floor((openPhish.snapshot_age_seconds % 3600) / 60)} m`
  return <><PageTitle eyebrow="COLLECTOR CONFIGURATION" title="Integrations" subtitle="Provider keys stay on the backend. Each investigation records availability and source status." />
    <section className="panel"><div className="panel-heading"><div><p className="eyebrow">SERVICE STATUS</p><h2>{isDemo ? 'Synthetic fixtures are active' : 'Live collector configuration'}</h2></div><span className={`mode-pill ${isDemo ? 'demo' : 'live'}`}><span className="status-dot" />{isDemo ? 'Demo data' : 'Live mode'}</span></div>
      <div className="integration-grid">{integrations.map((item) => <article className="integration-card" key={String(item.id)}><div className="card-top"><span className="card-icon cyan">⌘</span><span className="card-label">{String(item.id).toUpperCase()}</span><StatusBadge value={item.configured ? 'configured' : 'not configured'} /></div><h3>{String(item.name)}</h3><p>{String(item.behavior)}</p>{item.id === 'xposedornot' && <p className="tiny-note">No API key is used. Enable only when the deployment use is within the community endpoint's personal, low-volume scope. Workspace limits are shared across processes: at most 2/second, 25/hour, 100/day.</p>}{!item.configured && <p className="tiny-note">Set the backend environment variable for this service, then rebuild the API container.</p>}</article>)}</div>
      <div className="note-box">Live provider credentials are never returned by this page. Missing keys and provider outages appear as unavailable collector results; they are not replaced by synthetic findings.</div>
    </section>
    <section className="panel spamhaus-feed-panel" aria-labelledby="spamhaus-feed-heading">
      <div className="panel-heading"><div><p className="eyebrow">SHARED THREAT FEED</p><h2 id="spamhaus-feed-heading">Spamhaus DROP snapshot</h2></div><StatusBadge value={spamhausDrop?.freshness ?? 'unavailable'} /></div>
      {!spamhausDrop ? <p role="status">Snapshot status is unavailable.</p> : <>
        <p className="note-box">{spamhausDrop.coverage_note}</p>
        <dl className="feed-metadata-grid">
          <div><dt>Active snapshot</dt><dd>{spamhausDrop.snapshot_id ?? 'No validated snapshot'}</dd></div>
          <div><dt>Records</dt><dd>{spamhausDrop.snapshot_id ? spamhausDrop.record_count.toLocaleString() : 'Unavailable'}</dd></div>
          <div><dt>SHA-256</dt><dd><code>{spamhausDrop.content_sha256 ?? 'Unavailable'}</code></dd></div>
          <div><dt>Parser</dt><dd>{spamhausDrop.parser_version}</dd></div>
          <div><dt>Snapshot retrieved</dt><dd>{spamhausDrop.retrieved_at ? new Date(spamhausDrop.retrieved_at).toLocaleString() : 'Not retrieved'}</dd></div>
          <div><dt>Provider publication date</dt><dd>{spamhausDrop.published_at ? new Date(spamhausDrop.published_at).toLocaleString() : 'Unavailable'}</dd></div>
          <div><dt>Last successful revalidation</dt><dd>{spamhausDrop.last_successful_revalidation_at ? new Date(spamhausDrop.last_successful_revalidation_at).toLocaleString() : 'Not observed'}</dd></div>
          <div><dt>Age since revalidation</dt><dd>{age} · freshness limit {Math.floor(spamhausDrop.freshness_limit_seconds / 3600)} h</dd></div>
        </dl>
        <div className="feed-attribution"><strong>Attribution</strong><span>{spamhausDrop.attribution}</span>
          {Object.entries(feeds).map(([family, value]) => {
            const details = value && typeof value === 'object' ? value as Record<string, unknown> : {}
            const providerMeta = details.provider_metadata && typeof details.provider_metadata === 'object' ? details.provider_metadata as Record<string, unknown> : {}
            return <small key={family}>{family.toUpperCase()} · {providerMeta.copyright ? String(providerMeta.copyright) : 'Provider copyright unavailable'} · {details.published_at ? new Date(String(details.published_at)).toLocaleString() : 'date unavailable'}</small>
          })}
        </div>
        {spamhausDrop.latest_attempt && <div className="feed-attempt" role="status"><strong>Latest refresh: {spamhausDrop.latest_attempt.status}</strong><span>{new Date(spamhausDrop.latest_attempt.requested_at).toLocaleString()} · {spamhausDrop.latest_attempt.error_code ?? (spamhausDrop.latest_attempt.snapshot_id ? `snapshot ${spamhausDrop.latest_attempt.snapshot_id}` : 'no snapshot created')}</span></div>}
        {spamhausDrop.next_refresh_at && <p className="tiny-note">Next permitted refresh: {new Date(spamhausDrop.next_refresh_at).toLocaleString()} (daily provider cooldown).</p>}
        {canRefreshSpamhaus && <button className="small-button" disabled={isDemo || !spamhausDrop.enabled || attemptPending} onClick={onRefreshSpamhaus}>{attemptPending ? 'Refresh queued' : 'Queue feed refresh'}</button>}
        {isDemo && <p className="tiny-note">Demo mode uses a deterministic synthetic fixture. Refresh controls remain disabled and no provider request is made.</p>}
      </>}
    </section>
    <section className="panel spamhaus-feed-panel" aria-labelledby="cins-feed-heading">
      <div className="panel-heading"><div><p className="eyebrow">SHARED THREAT FEED</p><h2 id="cins-feed-heading">CINS Army IP snapshot</h2></div><StatusBadge value={cinsArmy?.freshness ?? 'unavailable'} /></div>
      {!cinsArmy ? <p role="status">CINS Army snapshot status is unavailable.</p> : <>
        <p className="note-box">{cinsArmy.coverage_note}</p>
        <dl className="feed-metadata-grid">
          <div><dt>Active snapshot</dt><dd>{cinsArmy.snapshot_id ?? 'No validated snapshot'}</dd></div>
          <div><dt>Exact IP indicators</dt><dd>{cinsArmy.snapshot_id ? cinsArmy.record_count.toLocaleString() : 'Unavailable'}</dd></div>
          <div><dt>SHA-256</dt><dd><code>{cinsArmy.content_sha256 ?? 'Unavailable'}</code></dd></div>
          <div><dt>Snapshot integrity check</dt><dd>{cinsArmy.integrity_valid === true ? 'Passed' : cinsArmy.integrity_valid === false ? 'Failed' : 'Unavailable'} · checksum detects later changes; it does not independently prove source authenticity.</dd></div>
          <div><dt>Parser</dt><dd>{cinsArmy.parser_version}</dd></div>
          <div><dt>Snapshot retrieved</dt><dd>{cinsArmy.retrieved_at ? new Date(cinsArmy.retrieved_at).toLocaleString() : 'Not retrieved'}</dd></div>
          <div><dt>Provider publication date</dt><dd>Not supplied by this feed</dd></div>
          <div><dt>Last successful revalidation</dt><dd>{cinsArmy.last_successful_revalidation_at ? new Date(cinsArmy.last_successful_revalidation_at).toLocaleString() : 'Not observed'}</dd></div>
          <div><dt>Age since revalidation</dt><dd>{cinsAge} · freshness limit {Math.floor(cinsArmy.freshness_limit_seconds / 3600)} h</dd></div>
        </dl>
        <div className="feed-attribution"><strong>Attribution</strong><span>{cinsArmy.attribution}</span>
          <small>Source: <a href="https://cinsscore.com/list/ci-badguys.txt" target="_blank" rel="noreferrer">official CINS Army text feed</a></small>
          <small>The 24-hour default is CyberLens configuration; it is not a claim about the provider's publication frequency.</small>
        </div>
        {cinsArmy.latest_attempt && <div className="feed-attempt" role="status"><strong>Latest refresh: {cinsArmy.latest_attempt.status}</strong><span>{new Date(cinsArmy.latest_attempt.requested_at).toLocaleString()} · {cinsArmy.latest_attempt.error_code ?? (cinsArmy.latest_attempt.snapshot_id ? `snapshot ${cinsArmy.latest_attempt.snapshot_id}` : 'no snapshot created')}</span></div>}
        {cinsArmy.next_refresh_at && <p className="tiny-note">Next CyberLens refresh interval: {new Date(cinsArmy.next_refresh_at).toLocaleString()}.</p>}
        {canRefreshCinsArmy && <button className="small-button" disabled={isDemo || !cinsArmy.enabled || cinsPending} onClick={onRefreshCinsArmy}>{cinsPending ? 'Refresh queued' : 'Queue feed refresh'}</button>}
        {isDemo && <p className="tiny-note">Demo uses synthetic reserved IPs. Refresh is disabled and no provider request is made.</p>}
      </>}
    </section>
    <section className="panel spamhaus-feed-panel" aria-labelledby="openphish-feed-heading">
      <div className="panel-heading"><div><p className="eyebrow">OPTIONAL URL INTELLIGENCE</p><h2 id="openphish-feed-heading">OpenPhish Community Feed</h2></div><StatusBadge value={openPhish?.freshness ?? 'unavailable'} /></div>
      {!openPhish ? <p role="status">OpenPhish status is unavailable.</p> : <>
        <p className="note-box">{openPhish.coverage_note}</p>
        <div className="feed-attribution" role="note">
          <strong>Provider terms and privacy</strong>
          <span>OpenPhish describes this community feed as for non-commercial personal use. Use that supports an organization's business operations, security operations, or product functions requires prior written provider consent. Do not disclose or distribute feed data without express permission. CyberLens settings record operator intent; they do not grant provider rights.</span>
          <span>With personal-only access, this Live workspace is restricted to its configured owner while the feed data is retained. The selected URL and feed results can appear in that owner's investigation evidence and reports.</span>
          <small><a href="https://www.openphish.com/terms.html" target="_blank" rel="noreferrer">Review current OpenPhish terms</a></small>
        </div>
        <dl className="feed-metadata-grid">
          <div><dt>Configuration</dt><dd>{openPhish.configuration_state.replaceAll('_', ' ')}</dd></div>
          <div><dt>Access scope</dt><dd>{openPhish.access_scope.replaceAll('_', ' ')}</dd></div>
          <div><dt>Active snapshot</dt><dd>{openPhish.snapshot_id ?? 'No validated snapshot'}</dd></div>
          <div><dt>URL records</dt><dd>{openPhish.snapshot_id ? openPhish.record_count.toLocaleString() : 'Unavailable'}</dd></div>
          <div><dt>SHA-256</dt><dd><code>{openPhish.content_sha256 ?? 'Unavailable'}</code></dd></div>
          <div><dt>Snapshot integrity</dt><dd>{openPhish.integrity_valid === true ? 'Passed' : openPhish.integrity_valid === false ? 'Failed' : 'Unavailable'} · checksum detects later changes; it does not independently prove source authenticity.</dd></div>
          <div><dt>Parser</dt><dd>{openPhish.parser_version}</dd></div>
          <div><dt>Retrieved</dt><dd>{openPhish.retrieved_at ? new Date(openPhish.retrieved_at).toLocaleString() : 'Not retrieved'}</dd></div>
          <div><dt>Last successful revalidation</dt><dd>{openPhish.last_successful_revalidation_at ? new Date(openPhish.last_successful_revalidation_at).toLocaleString() : 'Not observed'}</dd></div>
          <div><dt>Age since revalidation</dt><dd>{openPhishAge} · freshness limit {Math.floor(openPhish.freshness_limit_seconds / 3600)} h</dd></div>
        </dl>
        <div className="feed-attribution"><strong>Attribution</strong><span>{openPhish.attribution}</span><small>The 12-hour default is a CyberLens refresh interval. It does not guarantee provider publication timing.</small></div>
        {!openPhish.enabled && <p className="tiny-note">{openPhish.configuration_reason}</p>}
        {openPhish.latest_attempt && <div className="feed-attempt" role="status"><strong>Latest refresh: {openPhish.latest_attempt.status}</strong><span>{new Date(openPhish.latest_attempt.requested_at).toLocaleString()} · {openPhish.latest_attempt.error_code ?? (openPhish.latest_attempt.snapshot_id ? `snapshot ${openPhish.latest_attempt.snapshot_id}` : 'no snapshot created')}</span></div>}
        {openPhish.next_refresh_at && <p className="tiny-note">Next permitted CyberLens refresh: {new Date(openPhish.next_refresh_at).toLocaleString()}.</p>}
        {canRefreshOpenPhish && <button className="small-button" disabled={isDemo || !openPhish.enabled || openPhishPending} onClick={onRefreshOpenPhish}>{openPhishPending ? 'Refresh queued' : 'Queue feed refresh'}</button>}
        {isDemo && <p className="tiny-note">Demo uses a deterministic synthetic reserved-domain fixture. Refresh is disabled and no provider request is made.</p>}
      </>}
    </section>
  </>
}


