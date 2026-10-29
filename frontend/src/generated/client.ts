/** Small typed operation layer generated from the FastAPI OpenAPI contract. */
import { request } from '../api'
import type { operations } from './api'

type Json200<Operation> = Operation extends { responses: { 200: { content: { 'application/json': infer Body } } } } ? Body : never
type Query<Operation> = Operation extends { parameters: { query?: infer Value } } ? Value : never

export type ListAssetsQuery = Query<operations['list_assets_api_v1_assets_get']>
export type ListInvestigationsQuery = Query<operations['list_investigations_api_v1_investigations_get']>
export type ListIncidentsQuery = Query<operations['list_incidents_api_v1_incidents_get']>
export type ListReportsQuery = Query<operations['list_reports_api_v1_reports_get']>
export type ListFindingsQuery = Query<operations['list_findings_api_v1_findings_get']>
export type ListAuditEventsQuery = Query<operations['list_audit_events_api_v1_audit_events_get']>

function queryString(query: Record<string, unknown> | undefined): string {
  if (!query) return ''
  const params = new URLSearchParams()
  Object.entries(query).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') params.set(key, String(value)) })
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

export function listAssets(query?: ListAssetsQuery) {
  return request<Json200<operations['list_assets_api_v1_assets_get']>>(`/assets${queryString(query as Record<string, unknown> | undefined)}`)
}
export function listInvestigations(query?: ListInvestigationsQuery) {
  return request<Json200<operations['list_investigations_api_v1_investigations_get']>>(`/investigations${queryString(query as Record<string, unknown> | undefined)}`)
}
export function listIncidents(query?: ListIncidentsQuery) {
  return request<Json200<operations['list_incidents_api_v1_incidents_get']>>(`/incidents${queryString(query as Record<string, unknown> | undefined)}`)
}
export function listReports(query?: ListReportsQuery) {
  return request<Json200<operations['list_reports_api_v1_reports_get']>>(`/reports${queryString(query as Record<string, unknown> | undefined)}`)
}
export function listFindings(query?: ListFindingsQuery) {
  return request<Json200<operations['list_findings_api_v1_findings_get']>>(`/findings${queryString(query as Record<string, unknown> | undefined)}`)
}
export function listAuditEvents(query?: ListAuditEventsQuery) {
  return request<Json200<operations['list_audit_events_api_v1_audit_events_get']>>(`/audit-events${queryString(query as Record<string, unknown> | undefined)}`)
}
