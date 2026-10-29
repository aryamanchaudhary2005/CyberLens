import { useMemo } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { PostureRiskTrendPoint } from '../api'
import { useInitialMotion } from './motion'

const tooltipStyle = {
  background: 'var(--surface-raised)', border: '1px solid var(--border-strong)',
  borderRadius: 'var(--radius-sm)', color: 'var(--text)', fontFamily: 'var(--font-ui)',
  fontSize: 12, boxShadow: 'var(--shadow-menu)',
}
const tickStyle = { fill: 'var(--text-muted)', fontFamily: 'var(--font-ui)', fontSize: 12 }
const gridStroke = 'var(--border)'
const colors = Array.from({ length: 6 }, (_, index) => `var(--chart-${index + 1})`)
const animationDuration = 360

function periodLabel(value: unknown) {
  const date = new Date(String(value))
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

type RiskHistoryPoint = { name: string; score: number | null; policyVersion?: string | null }

export function RiskHistoryChart({ points }: { points: RiskHistoryPoint[] }) {
  const animate = useInitialMotion()
  const policyForPoint = (point: RiskHistoryPoint, index: number) => point.score == null ? null : point.policyVersion?.trim() || ('Unknown policy · ' + point.name + ' · ' + index)
  const policies = useMemo(() => Array.from(new Set(points.flatMap((point, index) => {
    const policy = policyForPoint(point, index)
    return policy ? [policy] : []
  }))), [points])
  const series = useMemo(() => points.map((point, index) => {
    const policy = policyForPoint(point, index)
    const row: Record<string, string | number | null> = { name: point.name }
    policies.forEach((version, policyIndex) => { row['score_' + policyIndex] = version === policy ? point.score : null })
    row.policyVersion = policy ?? 'No saved score'
    return row
  }), [points, policies])
  const summaries = useMemo(() => policies.map((policy, index) => ({ policy, key: 'score_' + index })), [policies])

  return <div className="chart-motion-frame" data-chart-motion={animate ? 'initial' : 'static'} data-chart-kind="risk-history">
    <ResponsiveContainer width="100%" height={220}><LineChart data={series} margin={{ top: 8, right: 12, left: 2, bottom: 6 }}>
      <CartesianGrid vertical={false} stroke={gridStroke} strokeDasharray="3 5" />
      <XAxis dataKey="name" tick={tickStyle} tickFormatter={periodLabel} minTickGap={20} interval="preserveStartEnd" axisLine={{ stroke: 'var(--border-strong)' }} tickLine={false} />
      <YAxis domain={[0, 100]} width={48} tick={tickStyle} axisLine={false} tickLine={false} label={{ value: 'Risk score / 100', angle: -90, position: 'insideLeft', fill: 'var(--text-muted)', fontSize: 11 }} />
      <Tooltip contentStyle={tooltipStyle} labelFormatter={(label) => 'Observed ' + String(label)} formatter={(value, name, item) => [
        value == null ? 'No saved score' : String(value) + ' / 100',
        String(item.payload?.policyVersion ?? name),
      ]} />
      {summaries.length > 1 && <Legend formatter={(value) => String(value)} wrapperStyle={{ paddingTop: 8, fontFamily: 'var(--font-ui)', fontSize: 12 }} />}
      {summaries.map((item, index) => <Line key={item.key} type="linear" dataKey={item.key} name={item.policy} stroke={colors[index % colors.length]} strokeWidth={2.5}
        dot={{ r: 3, fill: colors[index % colors.length], strokeWidth: 0 }} activeDot={{ r: 5, strokeWidth: 2, stroke: 'var(--text)' }}
        isAnimationActive={animate} animationId={0} animationDuration={animationDuration} animationEasing="ease-out" connectNulls={false} />)}
    </LineChart></ResponsiveContainer>
  </div>
}

type ChartTrendPoint = PostureRiskTrendPoint
type RiskSeries = { key: string; label: string; colorIndex: number }

function riskSeriesKey(point: ChartTrendPoint) {
  const versions = [...new Set(point.policy_versions ?? [])].sort()
  if (versions.length === 1) return { key: 'policy:' + versions[0], label: 'Policy ' + versions[0] }
  if (versions.length > 1) return { key: 'mixed:' + point.period_start, label: 'Mixed policies · ' + periodLabel(point.period_start) }
  return { key: 'unknown:' + point.period_start, label: 'Unknown policy · ' + periodLabel(point.period_start) }
}

export function PostureRiskChart({ points }: { points: ChartTrendPoint[] }) {
  const animate = useInitialMotion()
  const series = useMemo(() => {
    const pointKeys = points.map(riskSeriesKey)
    const allSeries: RiskSeries[] = []
    for (const item of pointKeys) if (!allSeries.some((seriesItem) => seriesItem.key === item.key)) {
      allSeries.push({ key: item.key, label: item.label, colorIndex: allSeries.length })
    }
    const rows = points.map((point, index) => {
      const row: Record<string, string | number | null> = { period_start: point.period_start }
      pointKeys.forEach((key, keyIndex) => { row['risk_' + keyIndex] = key.key === pointKeys[index].key ? point.average_score : null })
      return row
    })
    const lines = allSeries.map((item) => {
      const index = pointKeys.findIndex((key) => key.key === item.key)
      return { ...item, dataKey: 'risk_' + index }
    })
    return { rows, lines }
  }, [points])

  return <div className="chart-motion-frame" data-chart-motion={animate ? 'initial' : 'static'} data-chart-kind="posture-risk">
    <ResponsiveContainer width="100%" height={230}><LineChart data={series.rows} margin={{ top: 8, right: 12, left: 2, bottom: 6 }}>
      <CartesianGrid strokeDasharray="3 5" vertical={false} stroke={gridStroke} />
      <XAxis dataKey="period_start" tick={tickStyle} tickFormatter={periodLabel} minTickGap={20} interval="preserveStartEnd" axisLine={{ stroke: 'var(--border-strong)' }} tickLine={false} />
      <YAxis domain={[0, 100]} width={50} tick={tickStyle} axisLine={false} tickLine={false} label={{ value: 'Average score / 100', angle: -90, position: 'insideLeft', fill: 'var(--text-muted)', fontSize: 11 }} />
      <Tooltip contentStyle={tooltipStyle} labelFormatter={(label) => 'Period starts ' + periodLabel(label)} formatter={(value, name) => [
        value == null ? 'No saved score' : String(value) + ' / 100',
        String(series.lines.find((line) => line.dataKey === name)?.label ?? name),
      ]} />
      {series.lines.length > 1 && <Legend formatter={(value) => String(value)} wrapperStyle={{ paddingTop: 8, fontFamily: 'var(--font-ui)', fontSize: 12 }} />}
      {series.lines.map((line) => <Line key={line.key} type="linear" dataKey={line.dataKey} name={line.label} stroke={colors[line.colorIndex % colors.length]} strokeWidth={2.5}
        dot={{ r: 3, fill: colors[line.colorIndex % colors.length], strokeWidth: 0 }} activeDot={{ r: 5, strokeWidth: 2, stroke: 'var(--text)' }}
        isAnimationActive={animate} animationId={0} animationDuration={animationDuration} animationEasing="ease-out" connectNulls={false} />)}
    </LineChart></ResponsiveContainer>
  </div>
}

export function PostureWorkflowChart({ points }: { points: Array<{ period_start: string; investigations: number | null; monitoring: number | null }> }) {
  const animate = useInitialMotion()
  return <div className="chart-motion-frame" data-chart-motion={animate ? 'initial' : 'static'} data-chart-kind="workflow">
    <ResponsiveContainer width="100%" height={230}><BarChart data={points} margin={{ top: 8, right: 12, left: 2, bottom: 6 }}>
      <CartesianGrid strokeDasharray="3 5" vertical={false} stroke={gridStroke} />
      <XAxis dataKey="period_start" tick={tickStyle} tickFormatter={periodLabel} minTickGap={20} interval="preserveStartEnd" axisLine={{ stroke: 'var(--border-strong)' }} tickLine={false} />
      <YAxis allowDecimals={false} width={50} tick={tickStyle} axisLine={false} tickLine={false} label={{ value: 'Saved runs', angle: -90, position: 'insideLeft', fill: 'var(--text-muted)', fontSize: 11 }} />
      <Tooltip contentStyle={tooltipStyle} labelFormatter={(label) => 'Period starts ' + periodLabel(label)} formatter={(value, name) => [value == null ? 'Unavailable' : String(value) + ' runs', name]} />
      <Legend wrapperStyle={{ paddingTop: 8, fontFamily: 'var(--font-ui)', fontSize: 12 }} />
      <Bar dataKey="investigations" name="Investigations" fill={colors[0]} radius={[3, 3, 0, 0]} isAnimationActive={animate} animationId={0} animationDuration={animationDuration} animationEasing="ease-out" />
      <Bar dataKey="monitoring" name="Monitoring runs" fill={colors[1]} radius={[3, 3, 0, 0]} isAnimationActive={animate} animationId={0} animationDuration={animationDuration} animationEasing="ease-out" />
    </BarChart></ResponsiveContainer>
  </div>
}
