import type { Asset, Finding, Investigation, InvestigationAttempt, IpIntelligence, Risk } from '../api'

export type View = 'overview' | 'assets' | 'investigations' | 'incidents' | 'threat-model' | 'remediation' | 'reports' | 'integrity' | 'integrations' | 'admin'
export type InvestigationDetail = Investigation & {
  asset: Asset
  attempts: InvestigationAttempt[]
  collector_runs: Array<Record<string, unknown>>
  findings: Finding[]
  evidence: Array<Record<string, unknown>>
  risk: Risk | null
  ip_intelligence?: IpIntelligence | null
}
export type CpeResult = { cpe_name: string; title: string | null; deprecated: boolean }
