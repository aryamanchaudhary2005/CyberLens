import { useMemo, useRef, useState, type KeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react'
import type { EvidenceGraph, EvidenceGraphEdge, EvidenceGraphNode, GraphNodeType } from '../api'
import { useReducedMotionPreference } from './motion'

const CANVAS_WIDTH = 1100
const LANE_X: Record<GraphNodeType, number> = {
  asset: 90, domain: 290, ip: 290, certificate: 490, software: 490, cve: 490,
  finding: 690, investigation: 690, incident: 890, playbook_task: 890,
}
export const GRAPH_RENDER_LIMITS = { animatedNodes: 120, animatedEdges: 240 } as const

type Point = { x: number; y: number; domId: string }
type ViewBox = { x: number; y: number; width: number; height: number }

/** Deterministic type lanes; remembered coordinates keep old nodes fixed on refresh. */
export function layoutEvidenceNodes(nodes: EvidenceGraphNode[], previous = new Map<string, Point>()) {
  const points = new Map<string, Point>()
  const occupied = new Map<number, Set<number>>()
  const slotY = 78
  const slotStep = 118
  const laneFor = (node: EvidenceGraphNode) => LANE_X[node.type]
  for (const node of nodes) {
    const point = previous.get(node.id)
    if (!point) continue
    points.set(node.id, point)
    const lane = laneFor(node)
    const slots = occupied.get(lane) ?? new Set<number>()
    slots.add(Math.max(0, Math.round((point.y - slotY) / slotStep)))
    occupied.set(lane, slots)
  }
  const sorted = nodes.slice().sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id))
  for (const node of sorted) {
    if (points.has(node.id)) continue
    const lane = laneFor(node)
    const slots = occupied.get(lane) ?? new Set<number>()
    let slot = 0
    while (slots.has(slot)) slot += 1
    slots.add(slot)
    occupied.set(lane, slots)
    points.set(node.id, { x: lane, y: slotY + slot * slotStep, domId: `evidence-node-${points.size}` })
  }
  // Stable DOM ids are based on the node's index in the API projection, not on labels.
  nodes.forEach((node, index) => {
    const point = points.get(node.id)
    if (point) points.set(node.id, { ...point, domId: `evidence-node-${index}` })
  })
  const maxY = Math.max(slotY, ...Array.from(points.values(), (point) => point.y))
  return { points, width: CANVAS_WIDTH, height: Math.max(280, maxY + 92) }
}

function displayName(value: string) { return value.replaceAll('_', ' ') }
function asText(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return null
}
function nodeSymbol(type: GraphNodeType) {
  return ({ asset: 'A', domain: 'D', ip: 'IP', certificate: 'TLS', software: 'SW', cve: 'CVE', finding: 'F', investigation: 'RUN', incident: 'INC', playbook_task: 'TASK' } satisfies Record<GraphNodeType, string>)[type]
}
function EdgeLine({ edge, from, to, selected, highlighted, dimmed, onSelect }: { edge: EvidenceGraphEdge; from: Point; to: Point; selected: boolean; highlighted: boolean; dimmed: boolean; onSelect: () => void }) {
  const label = displayName(edge.relationship_type)
  const middleX = (from.x + to.x) / 2
  const middleY = (from.y + to.y) / 2
  return <g className={`graph-edge ${edge.evidence_role}${selected ? ' selected' : ''}${highlighted ? ' highlighted' : ''}${dimmed ? ' dimmed' : ''}`} role="button" tabIndex={0}
    aria-label={`${edge.evidence_role} relationship: ${label}. Source ${edge.source}. Observed ${edge.observed_at}. Evidence ${edge.evidence_id}.`}
    onClick={onSelect} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect() } }}>
    <title>{`${label} · ${edge.source} · ${edge.observed_at} · Evidence ${edge.evidence_id}`}</title>
    <line className="graph-edge-hit" x1={from.x} y1={from.y} x2={to.x} y2={to.y} />
    <line className="graph-edge-line" x1={from.x} y1={from.y} x2={to.x} y2={to.y} />
    {selected && <>
      <rect className="graph-edge-label-bg" x={middleX - Math.min(96, label.length * 3.1 + 8)} y={middleY - 22} width={Math.min(192, label.length * 6.2 + 16)} height="17" rx="5" />
      <text className="graph-edge-label" x={middleX} y={middleY - 10}>{label.length > 26 ? `${label.slice(0, 23)}…` : label}</text>
      <g className="graph-evidence-marker" transform={`translate(${middleX - 12} ${middleY + 5})`} aria-hidden="true">
        <rect width="24" height="18" rx="5" /><text x="12" y="12">EV</text>
      </g>
    </>}
  </g>
}

function NodeShape({ type }: { type: GraphNodeType }) {
  if (type === 'asset') return <rect x="-29" y="-20" width="58" height="40" rx="9" />
  if (type === 'software') return <polygon points="-27,-15 -15,-25 15,-25 27,-15 27,15 15,25 -15,25 -27,15" />
  if (type === 'cve') return <polygon points="0,-29 29,0 0,29 -29,0" />
  if (type === 'finding') return <path d="M0-29 30 24H-30Z" />
  if (type === 'incident') return <polygon points="-16,-27 16,-27 28,-15 28,15 16,27 -16,27 -28,15 -28,-15" />
  if (type === 'certificate') return <path d="M0-29 25-19v17c0 15-10 25-25 32C-15 23-25 13-25-2v-17Z" />
  if (type === 'investigation') return <rect x="-30" y="-21" width="60" height="42" rx="13" strokeDasharray="4 3" />
  if (type === 'playbook_task') return <path d="M-19-26h29l12 12v40h-41Z M10-26v12h12" />
  return <ellipse rx="30" ry="23" />
}

function valueDetails(details: Record<string, unknown>) {
  return Object.entries(details).filter(([key]) => key !== 'from_label' && key !== 'to_label').slice(0, 12).map(([key, value]) => {
    let text = asText(value)
    if (text === null && value != null) {
      try { text = JSON.stringify(value) ?? '[unavailable]' } catch { text = '[unavailable]' }
    }
    return { key: displayName(key), value: text ?? 'Not recorded' }
  })
}

type EvidenceGraphExplorerProps = { graph: EvidenceGraph; evidence: Array<Record<string, unknown>> }
export function EvidenceGraphExplorer({ graph, evidence }: EvidenceGraphExplorerProps) {
  const reducedMotion = useReducedMotionPreference()
  const largeGraph = graph.nodes.length > GRAPH_RENDER_LIMITS.animatedNodes || graph.edges.length > GRAPH_RENDER_LIMITS.animatedEdges
  const [display, setDisplay] = useState<'graph' | 'list'>('graph')
  const [nodeType, setNodeType] = useState('all')
  const [relationshipType, setRelationshipType] = useState('all')
  const [evidenceRole, setEvidenceRole] = useState('all')
  const [selectedNodeId, setSelectedNodeId] = useState('')
  const [selectedEdgeId, setSelectedEdgeId] = useState('')
  const [query, setQuery] = useState('')
  const [viewBox, setViewBox] = useState<ViewBox | null>(null)
  const [panning, setPanning] = useState(false)
  const canvasRef = useRef<SVGSVGElement | null>(null)
  const positionCache = useRef<{ investigationId: string; points: Map<string, Point> }>({ investigationId: graph.investigation_id, points: new Map() })
  const panStart = useRef<{ pointerId: number; x: number; y: number; view: ViewBox } | null>(null)
  if (positionCache.current.investigationId !== graph.investigation_id) positionCache.current = { investigationId: graph.investigation_id, points: new Map() }

  const layout = useMemo(() => {
    const next = layoutEvidenceNodes(graph.nodes, positionCache.current.points)
    positionCache.current.points = next.points
    return next
  }, [graph.investigation_id, graph.nodes])
  const fullView = { x: 0, y: 0, width: layout.width, height: layout.height }
  const currentView = viewBox ?? fullView
  const nodeTypes = useMemo(() => Array.from(new Set(graph.nodes.map((node) => node.type))).sort(), [graph.nodes])
  const relationshipTypes = useMemo(() => Array.from(new Set(graph.edges.map((edge) => edge.relationship_type))).sort(), [graph.edges])
  const visibleNodes = useMemo(() => graph.nodes.filter((node) => nodeType === 'all' || node.type === nodeType), [graph.nodes, nodeType])
  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes])
  const visibleEdges = useMemo(() => graph.edges.filter((edge) =>
    (relationshipType === 'all' || edge.relationship_type === relationshipType) &&
    (evidenceRole === 'all' || edge.evidence_role === evidenceRole) &&
    visibleNodeIds.has(edge.from_node_id) && visibleNodeIds.has(edge.to_node_id)),
  [graph.edges, relationshipType, evidenceRole, visibleNodeIds])
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId)
  const selectedEdge = graph.edges.find((edge) => edge.id === selectedEdgeId)
  const matchingNodes = query.trim() ? graph.nodes.filter((node) => `${node.label} ${node.type}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())).slice(0, 10) : []
  const evidenceById = useMemo(() => new Map(evidence.map((item) => [String(item.id ?? ''), item])), [evidence])
  const neighborhoodEdges = useMemo(() => new Set(graph.edges.filter((edge) => selectedNode && (edge.from_node_id === selectedNode.id || edge.to_node_id === selectedNode.id)).map((edge) => edge.id)), [graph.edges, selectedNode])
  const neighborhoodNodes = useMemo(() => new Set(graph.edges.filter((edge) => selectedEdge ? edge.id === selectedEdge.id : selectedNode && neighborhoodEdges.has(edge.id)).flatMap((edge) => [edge.from_node_id, edge.to_node_id])), [graph.edges, selectedEdge, selectedNode, neighborhoodEdges])
  const selectedNodeEdges = selectedNode ? graph.edges.filter((edge) => edge.from_node_id === selectedNode.id || edge.to_node_id === selectedNode.id) : []
  const isFiltered = visibleNodes.length !== graph.nodes.length || visibleEdges.length !== graph.edges.length

  function activateNode(node: EvidenceGraphNode) {
    setSelectedNodeId(node.id); setSelectedEdgeId('')
  }
  function activateEdge(edge: EvidenceGraphEdge) {
    setSelectedEdgeId(edge.id); setSelectedNodeId('')
  }
  function zoomBy(factor: number) {
    const centerX = currentView.x + currentView.width / 2
    const centerY = currentView.y + currentView.height / 2
    const width = Math.max(layout.width / 3.5, Math.min(layout.width * 1.5, currentView.width * factor))
    const height = Math.max(Math.min(260, layout.height), Math.min(layout.height * 1.5, currentView.height * factor))
    setViewBox({ x: centerX - width / 2, y: centerY - height / 2, width, height })
  }
  function fitToView() {
    const points = visibleNodes.map((node) => layout.points.get(node.id)).filter((point): point is Point => Boolean(point))
    if (!points.length) { setViewBox(fullView); return }
    const minX = Math.min(...points.map((point) => point.x))
    const maxX = Math.max(...points.map((point) => point.x))
    const minY = Math.min(...points.map((point) => point.y))
    const maxY = Math.max(...points.map((point) => point.y))
    const width = Math.min(layout.width, Math.max(280, maxX - minX + 150))
    const height = Math.min(layout.height, Math.max(250, maxY - minY + 135))
    setViewBox({ x: (minX + maxX - width) / 2, y: (minY + maxY - height) / 2, width, height })
  }
  function panBy(dx: number, dy: number) {
    setViewBox({ ...currentView, x: currentView.x + dx * currentView.width, y: currentView.y + dy * currentView.height })
  }
  function focusNode(node: EvidenceGraphNode) {
    setNodeType('all')
    activateNode(node)
    const point = layout.points.get(node.id)
    if (point) {
      const width = Math.min(layout.width, 450)
      const height = Math.min(layout.height, 410)
      setViewBox({ x: point.x - width / 2, y: point.y - height / 2, width, height })
      const domId = layout.points.get(node.id)?.domId
      window.requestAnimationFrame(() => document.getElementById(domId ?? '')?.focus())
    }
    setQuery('')
  }
  function handleSvgKeyDown(event: KeyboardEvent<SVGSVGElement>) {
    const dx = .16; const dy = .16
    if (event.key === 'ArrowLeft') { event.preventDefault(); panBy(-dx, 0) }
    else if (event.key === 'ArrowRight') { event.preventDefault(); panBy(dx, 0) }
    else if (event.key === 'ArrowUp') { event.preventDefault(); panBy(0, -dy) }
    else if (event.key === 'ArrowDown') { event.preventDefault(); panBy(0, dy) }
    else if (event.key === '+' || event.key === '=') { event.preventDefault(); zoomBy(.8) }
    else if (event.key === '-') { event.preventDefault(); zoomBy(1.25) }
    else if (event.key === 'Home') { event.preventDefault(); fitToView() }
  }
  function pointerDown(event: ReactPointerEvent<HTMLElement>) {
    if (event.button !== 0 || event.pointerType !== 'mouse') return
    if (event.target instanceof Element && event.target.closest('.graph-node, .graph-edge')) return
    event.stopPropagation()
    event.currentTarget.setPointerCapture(event.pointerId)
    panStart.current = { pointerId: event.pointerId, x: event.clientX, y: event.clientY, view: currentView }
    setPanning(true)
  }
  function pointerMove(event: ReactPointerEvent<HTMLElement>) {
    const start = panStart.current
    if (!start || start.pointerId !== event.pointerId) return
    const bounds = canvasRef.current?.getBoundingClientRect()
    if (!bounds || !bounds.width || !bounds.height) return
    setViewBox({ ...start.view,
      x: start.view.x - (event.clientX - start.x) * start.view.width / bounds.width,
      y: start.view.y - (event.clientY - start.y) * start.view.height / bounds.height,
    })
  }
  function pointerUp(event: ReactPointerEvent<HTMLElement>) {
    if (panStart.current?.pointerId !== event.pointerId) return
    panStart.current = null; setPanning(false)
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId)
  }
  function edgeMetadata(edge: EvidenceGraphEdge) {
    const row = evidenceById.get(edge.evidence_id)
    const payload = row?.evidence_json && typeof row.evidence_json === 'object' ? row.evidence_json as Record<string, unknown> : {}
    const provenance = payload.provenance && typeof payload.provenance === 'object' ? payload.provenance as Record<string, unknown> : {}
    const freshness = asText(payload.freshness ?? payload.provider_freshness ?? provenance.freshness)
    const applicability = asText(edge.details.applicability ?? payload.applicability)
    return { row, freshness: freshness ?? 'Not supplied by this evidence source', applicability: applicability ?? 'Not recorded for this relationship' }
  }
  function relationshipButton(edge: EvidenceGraphEdge) {
    const from = graph.nodes.find((node) => node.id === edge.from_node_id)
    const to = graph.nodes.find((node) => node.id === edge.to_node_id)
    return <button className="graph-detail-relationship" key={edge.id} onClick={() => activateEdge(edge)}>
      <span className={`graph-role-symbol ${edge.evidence_role}`} aria-hidden="true">{edge.evidence_role === 'direct' ? '━━' : '┄┄'}</span>
      <span><strong>{from?.label ?? edge.from_node_id} → {to?.label ?? edge.to_node_id}</strong><small>{displayName(edge.relationship_type)} · {edge.source} · {new Date(edge.observed_at).toLocaleString()}</small><small>Evidence {edge.evidence_id} · {edge.data_mode.toUpperCase()}</small></span>
    </button>
  }

  return <div className={`graph-explorer${largeGraph ? ' large-graph' : ''}`} data-render-profile={largeGraph ? 'simplified' : 'full'} data-node-count={graph.nodes.length} data-edge-count={graph.edges.length}>
    <div className="graph-display-toggle" role="group" aria-label="Graph presentation">
      <button type="button" className="small-button" aria-pressed={display === 'graph'} onClick={() => setDisplay('graph')}>Interactive graph</button>
      <button type="button" className="small-button" aria-pressed={display === 'list'} onClick={() => setDisplay('list')}>Evidence list</button>
    </div>
    <div className="graph-toolbar graph-filter-toolbar" role="group" aria-label="Evidence graph filters and controls">
      <label>Node type<select aria-label="Filter graph by node type" value={nodeType} onChange={(event) => setNodeType(event.target.value)}><option value="all">All node types</option>{nodeTypes.map((type) => <option key={type} value={type}>{displayName(type)}</option>)}</select></label>
      <label>Relationship<select aria-label="Filter graph by relationship type" value={relationshipType} onChange={(event) => setRelationshipType(event.target.value)}><option value="all">All relationships</option>{relationshipTypes.map((type) => <option key={type} value={type}>{displayName(type)}</option>)}</select></label>
      <label>Evidence role<select aria-label="Filter graph by evidence role" value={evidenceRole} onChange={(event) => setEvidenceRole(event.target.value)}><option value="all">All evidence roles</option><option value="direct">Direct evidence</option><option value="contextual">Contextual relationship</option></select></label>
      <label className="graph-search-label">Find a node<input type="search" aria-label="Search graph nodes" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && matchingNodes[0]) { event.preventDefault(); focusNode(matchingNodes[0]) } }} placeholder="Search saved labels" autoComplete="off" /></label>
      {matchingNodes.length > 0 && <ul className="graph-search-results" role="listbox" aria-label="Matching graph nodes">{matchingNodes.map((node) => <li key={node.id}><button type="button" role="option" aria-selected={selectedNodeId === node.id} onClick={() => focusNode(node)}>{node.label}<small>{displayName(node.type)}</small></button></li>)}</ul>}
    </div>
    {query.trim() && !matchingNodes.length && <p className="graph-filter-state" role="status">No saved graph node matches “{query}”.</p>}
    <div className="graph-navigation" role="group" aria-label="Graph navigation controls">
      <button type="button" className="small-button" aria-label="Zoom in" onClick={() => zoomBy(.8)}>＋ Zoom in</button>
      <button type="button" className="small-button" aria-label="Zoom out" onClick={() => zoomBy(1.25)}>− Zoom out</button>
      <button type="button" className="small-button" onClick={() => setViewBox(fullView)}>Reset view</button>
      <button type="button" className="small-button" onClick={fitToView}>Fit visible nodes</button>
      <span className="graph-pan-controls" role="group" aria-label="Pan graph with buttons">
        <button type="button" className="small-button" aria-label="Pan graph left" onClick={() => panBy(-.16, 0)}>←</button>
        <button type="button" className="small-button" aria-label="Pan graph up" onClick={() => panBy(0, -.16)}>↑</button>
        <button type="button" className="small-button" aria-label="Pan graph down" onClick={() => panBy(0, .16)}>↓</button>
        <button type="button" className="small-button" aria-label="Pan graph right" onClick={() => panBy(.16, 0)}>→</button>
      </span>
      <span className="graph-pan-handle" aria-hidden="true" title="Drag to pan; use the arrow buttons or graph keyboard shortcuts as alternatives" onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={pointerUp} onPointerCancel={pointerUp}>↕ Drag to pan</span>
    </div>
    {isFiltered && <p className="graph-filter-state" role="status">Filtered view: showing {visibleNodes.length} of {graph.nodes.length} nodes and {visibleEdges.length} of {graph.edges.length} evidence relationships.</p>}
    {largeGraph && <p className="graph-large-state" role="status">Large projection: all {graph.nodes.length} nodes and {graph.edges.length} relationships are retained. Entrance effects are off and labels are shortened; use search and filters to focus the view.</p>}
    <p className="graph-keyboard-help">Keyboard: focus the graph and use arrow keys to pan, +/− to zoom, Home to fit. Node and relationship controls use Enter or Space. Page scrolling and browser zoom remain unchanged.</p>
    <div className="graph-legend" aria-label="Evidence graph legend">
      <span><i className="graph-role-line direct" aria-hidden="true" />Direct evidence · solid line</span>
      <span><i className="graph-role-line contextual" aria-hidden="true" />Contextual relationship · dashed line</span>
      <span className="graph-legend-shape"><b>EV</b>Evidence record referenced by a selected relationship</span>
    </div>
    {graph.nodes.length > 0 && display === 'graph' && <div className="graph-canvas-scroll" onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={pointerUp} onPointerCancel={pointerUp}>
      <svg ref={canvasRef} className={`graph-canvas${panning ? ' is-panning' : ''}`} viewBox={`${currentView.x} ${currentView.y} ${currentView.width} ${currentView.height}`} role="group" aria-label="Interactive evidence relationship graph" tabIndex={0} aria-keyshortcuts="ArrowLeft ArrowRight ArrowUp ArrowDown + - Home"
        onKeyDown={handleSvgKeyDown}>
        {visibleEdges.map((edge) => {
          const from = layout.points.get(edge.from_node_id); const to = layout.points.get(edge.to_node_id)
          if (!from || !to) return null
          const selected = selectedEdgeId === edge.id
          const dimmed = Boolean((selectedNode && !neighborhoodEdges.has(edge.id)) || (selectedEdge && !selected))
          const highlighted = Boolean(selected || (selectedNode && neighborhoodEdges.has(edge.id)))
          return <EdgeLine key={edge.id} edge={edge} from={from} to={to} selected={selected} highlighted={highlighted} dimmed={dimmed} onSelect={() => activateEdge(edge)} />
        })}
        {visibleNodes.map((node) => {
          const point = layout.points.get(node.id)
          if (!point) return null
          const selected = selectedNodeId === node.id
          const dimmed = Boolean((selectedNode && !selected && !neighborhoodNodes.has(node.id)) || (selectedEdge && !neighborhoodNodes.has(node.id)))
          const labelLimit = largeGraph ? 16 : 25
          const label = node.label.length > labelLimit ? `${node.label.slice(0, labelLimit - 1)}…` : node.label
          return <g key={node.id} id={point.domId} data-node-id={node.id} transform={`translate(${point.x} ${point.y})`} className={`graph-node ${node.type}${selected ? ' selected' : ''}${dimmed ? ' dimmed' : ''}${!largeGraph && !reducedMotion ? ' graph-node-enter' : ''}`} role="button" tabIndex={0}
            aria-label={`${displayName(node.type)}: ${node.label}`} aria-pressed={selected} onClick={() => activateNode(node)}
            onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activateNode(node) } }}>
            <title>{node.label}</title><NodeShape type={node.type} /><text className="graph-node-symbol" x="0" y="3">{nodeSymbol(node.type)}</text>
            <text className="graph-node-label" x="0" y="46">{label}</text>
          </g>
        })}
      </svg>
    </div>}
    {graph.nodes.length > 0 && display === 'list' && <div className="graph-accessible-list">
      <h4>Nodes ({visibleNodes.length})</h4>
      {visibleNodes.length ? <ul className="graph-list graph-node-list" aria-label="Graph nodes">{visibleNodes.map((node) => <li key={node.id}><button className="graph-list-link" aria-pressed={selectedNodeId === node.id} onClick={() => activateNode(node)}><span className={`graph-node-kind ${node.type}`}>{nodeSymbol(node.type)}</span><strong>{node.label}</strong><span>{displayName(node.type)}</span></button></li>)}</ul> : <p className="graph-filter-state">No nodes match these filters.</p>}
      <h4>Evidence relationships ({visibleEdges.length})</h4>
      {visibleEdges.length ? <ol className="graph-list" aria-label="Evidence relationships">{visibleEdges.map((edge) => <li key={edge.id}><button className="graph-list-link" aria-pressed={selectedEdgeId === edge.id} onClick={() => activateEdge(edge)}>
        <span className={`graph-role-symbol ${edge.evidence_role}`} aria-hidden="true">{edge.evidence_role === 'direct' ? '━━' : '┄┄'}</span>
        <strong>{graph.nodes.find((node) => node.id === edge.from_node_id)?.label ?? edge.from_node_id}</strong><span>{displayName(edge.relationship_type)}</span><strong>{graph.nodes.find((node) => node.id === edge.to_node_id)?.label ?? edge.to_node_id}</strong>
      </button><small>{edge.evidence_role === 'direct' ? 'Direct evidence' : 'Contextual relationship'} · {edge.source} · {new Date(edge.observed_at).toLocaleString()} · {edge.data_mode.toUpperCase()} · Evidence {edge.evidence_id}</small></li>)}</ol> : <p className="graph-filter-state">No saved relationships match these filters.</p>}
    </div>}
    {!graph.nodes.length && <p className="graph-filter-state" role="status">No evidence nodes are in this saved projection. An empty projection is not a clean result.</p>}

    {(selectedNode || selectedEdge) && <section className="graph-selection" aria-live="polite" aria-label="Selected graph record details">
      {selectedNode && <>
        <div className="graph-selection-heading"><span className={`graph-node-kind ${selectedNode.type}`}>{nodeSymbol(selectedNode.type)}</span><div><p className="eyebrow">SELECTED NODE · {displayName(selectedNode.type)}</p><h4>{selectedNode.label}</h4></div></div>
        {Object.keys(selectedNode.details).length > 0 && <dl className="graph-detail-fields">{valueDetails(selectedNode.details).map((item) => <div key={item.key}><dt>{item.key}</dt><dd>{item.value}</dd></div>)}</dl>}
        <h5>Supported relationships ({selectedNodeEdges.length})</h5>
        {selectedNodeEdges.length ? <div className="graph-related-edges">{selectedNodeEdges.map(relationshipButton)}</div> : <p>No saved relationships are attached to this node.</p>}
      </>}
      {selectedEdge && (() => {
        const from = graph.nodes.find((node) => node.id === selectedEdge.from_node_id)
        const to = graph.nodes.find((node) => node.id === selectedEdge.to_node_id)
        const metadata = edgeMetadata(selectedEdge)
        return <>
          <div className="graph-selection-heading"><span className={`graph-role-symbol ${selectedEdge.evidence_role}`} aria-hidden="true">{selectedEdge.evidence_role === 'direct' ? '━━' : '┄┄'}</span><div><p className="eyebrow">SELECTED RELATIONSHIP · {selectedEdge.evidence_role === 'direct' ? 'DIRECT EVIDENCE' : 'CONTEXTUAL'}</p><h4>{from?.label ?? selectedEdge.from_node_id} → {to?.label ?? selectedEdge.to_node_id}</h4><p>{displayName(selectedEdge.relationship_type)}</p></div></div>
          <dl className="graph-detail-fields">
            <div><dt>Source / provider</dt><dd>{selectedEdge.source} · collector {selectedEdge.collector}</dd></div>
            <div><dt>Observed</dt><dd><time dateTime={selectedEdge.observed_at}>{new Date(selectedEdge.observed_at).toLocaleString()}</time></dd></div>
            <div><dt>Evidence reference</dt><dd><code>{selectedEdge.evidence_id}</code>{metadata.row && typeof metadata.row.sha256 === 'string' ? <small>SHA-256 {metadata.row.sha256}</small> : null}</dd></div>
            <div><dt>Freshness</dt><dd>{metadata.freshness}</dd></div>
            <div><dt>Applicability</dt><dd>{metadata.applicability}</dd></div>
            <div><dt>Mode / evidence role</dt><dd>{selectedEdge.data_mode.toUpperCase()} · {selectedEdge.evidence_role}</dd></div>
          </dl>
          {Object.keys(selectedEdge.details).filter((key) => !['from_label', 'to_label'].includes(key)).length > 0 && <details className="graph-context-details"><summary>Relationship context</summary><dl className="graph-detail-fields">{valueDetails(selectedEdge.details).map((item) => <div key={item.key}><dt>{item.key}</dt><dd>{item.value}</dd></div>)}</dl></details>}
        </>
      })()}
    </section>}
  </div>
}
