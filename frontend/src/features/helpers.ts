export const scenarios = [
  ['routine_website', 'Routine website'], ['suspicious_website', 'Suspicious website'],
  ['exposed_email', 'Exposed email'], ['vulnerable_application', 'Vulnerable application'], ['provider_outage', 'Provider outage'],
  ['ip_cins_only', 'IP: CINS Army only · use 198.51.100.23'], ['ip_overlap', 'IP: listed by both · use 203.0.113.42'],
  ['ip_no_match', 'IP: neither source lists it · use 192.0.2.44'], ['ip_provider_outage', 'IP: CINS Army outage · use 203.0.113.43'],
  ['openphish_match', 'URL: OpenPhish exact match · use synthetic feed URL'],
  ['openphish_overlap', 'URL: OpenPhish and VirusTotal overlap · use synthetic feed URL'],
  ['openphish_no_match', 'URL: OpenPhish no match'],
  ['openphish_outage', 'URL: OpenPhish provider outage'],
] as const

export function date(value: string) { const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString() }
export function message(reason: unknown) { return reason instanceof Error ? reason.message : 'The request could not be completed.' }
export function severityPriority(severity: string) { return severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : severity === 'medium' ? 'medium' : 'low' }
export function nextStatuses(status: string) { return status === 'new' ? ['triaged'] : status === 'triaged' ? ['responding', 'resolved'] : status === 'responding' ? ['resolved'] : status === 'resolved' ? ['closed'] : [] }
export function scenariosForKind(kind: string) {
  const allowed = kind === 'email' ? ['exposed_email', 'provider_outage'] : kind === 'application' ? ['vulnerable_application', 'provider_outage'] : kind === 'ip' ? ['suspicious_website', 'provider_outage', 'ip_cins_only', 'ip_overlap', 'ip_no_match', 'ip_provider_outage'] : kind === 'url' ? ['routine_website', 'suspicious_website', 'provider_outage', 'openphish_match', 'openphish_overlap', 'openphish_no_match', 'openphish_outage'] : ['routine_website', 'suspicious_website', 'provider_outage']
  return scenarios.filter(([id]) => allowed.includes(id))
}
export function defaultScenario(kind: string) { return kind === 'email' ? 'exposed_email' : kind === 'application' ? 'vulnerable_application' : 'routine_website' }
