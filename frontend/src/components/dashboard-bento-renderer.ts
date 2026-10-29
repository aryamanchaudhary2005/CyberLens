type Point = { x: number; y: number; z: number }

// Deterministic Fibonacci sphere: no random topology changes on React remounts.
const points: Point[] = Array.from({ length: 96 }, (_, i) => {
  const y = 1 - 2 * (i + .5) / 96
  const radius = Math.sqrt(1 - y * y)
  const angle = i * Math.PI * (3 - Math.sqrt(5))
  return { x: Math.cos(angle) * radius, y, z: Math.sin(angle) * radius }
})
const edges: [number, number][] = []
for (let i = 0; i < points.length; i++) for (let j = i + 1; j < points.length; j++) {
  const a = points[i], b = points[j]
  if ((a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2 < .23) edges.push([i, j])
}

export function createBentoRenderer(canvas: HTMLCanvasElement) {
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('Decorative canvas unavailable')
  let width = 900, height = 180, frame = 0, elapsed = 0, previous = 0, lastDraw = 0
  let running = false, disposed = false, frames = 0
  const draw = () => {
    ctx.clearRect(0, 0, width, height)
    const cell = width / 3, radius = Math.min(cell * .37, height * .4), cy = height / 2
    const angle = elapsed * .14, c = Math.cos(angle), s = Math.sin(angle)
    const projected = points.map(p => ({ x: p.x * c + p.z * s, y: p.y, z: p.z * c - p.x * s }))
    // Network sphere: rear edges are deliberately quieter, with no traffic claims.
    for (const [i, j] of edges) {
      const a = projected[i], b = projected[j], depth = (a.z + b.z + 2) / 4
      ctx.strokeStyle = `rgba(175,166,255,${.08 + depth * .48})`
      ctx.lineWidth = .7 + depth * .4
      ctx.beginPath(); ctx.moveTo(cell / 2 + a.x * radius, cy + a.y * radius); ctx.lineTo(cell / 2 + b.x * radius, cy + b.y * radius); ctx.stroke()
    }
    projected.forEach(p => {
      ctx.fillStyle = `rgba(218,211,255,${.15 + (p.z + 1) * .32})`
      ctx.beginPath(); ctx.arc(cell / 2 + p.x * radius, cy + p.y * radius, 1 + (p.z + 1) * .45, 0, Math.PI * 2); ctx.fill()
    })
    // Locally drawn floating layers replace the reference's remote pyramid image.
    for (let layer = 4; layer >= 0; layer--) {
      const size = radius * (.34 + layer * .17), y = cy - radius * .6 + layer * radius * .29 + Math.sin(elapsed * .8 + layer * .55) * radius * .045
      const turn = Math.sin(elapsed * .12) * .12
      const corners = Array.from({ length: 4 }, (_, i) => {
        const a = Math.PI / 2 * i + turn
        return { x: cell * 1.5 + Math.cos(a) * size, y: y + Math.sin(a) * size * .46 }
      })
      ctx.beginPath(); corners.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y)); ctx.closePath()
      ctx.fillStyle = `rgba(109,93,246,${.16 + layer * .025})`; ctx.fill()
      ctx.strokeStyle = 'rgba(175,166,255,.65)'; ctx.lineWidth = 1; ctx.stroke()
    }
    // Radial halftone, matching the supplied ripple without rapid flashing.
    const spacing = Math.max(10, radius / 7)
    for (let x = -7; x <= 7; x++) for (let y = -6; y <= 6; y++) {
      const distance = Math.sqrt(x * x + y * y), wave = .5 + .5 * Math.sin(distance * .65 - elapsed * 1.3)
      ctx.fillStyle = `rgba(175,166,255,${(.2 + wave * .45) * Math.max(0, 1 - distance / 10)})`
      ctx.beginPath(); ctx.arc(cell * 2.5 + x * spacing, cy + y * spacing, .8 + wave * 2.2, 0, Math.PI * 2); ctx.fill()
    }
    canvas.dataset.frames = String(++frames)
  }
  const resize = () => {
    if (disposed) return
    const rect = canvas.getBoundingClientRect()
    width = Math.max(1, rect.width); height = Math.max(1, rect.height)
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5, 1600 / width)
    canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); draw()
  }
  const tick = (now: number) => {
    if (!running || disposed) return
    if (previous) elapsed += Math.min((now - previous) / 1000, .1)
    previous = now
    if (now - lastDraw >= 1000 / 30) { draw(); lastDraw = now }
    frame = requestAnimationFrame(tick)
  }
  resize()
  let observer: ResizeObserver | undefined
  try { observer = new ResizeObserver(resize); observer.observe(canvas) } catch { observer?.disconnect() }
  window.addEventListener('resize', resize)
  return {
    setRunning(value: boolean) {
      if (disposed || running === value) return
      running = value; previous = 0
      if (value) frame = requestAnimationFrame(tick)
      else cancelAnimationFrame(frame)
    },
    dispose() { disposed = true; running = false; cancelAnimationFrame(frame); observer?.disconnect(); window.removeEventListener('resize', resize) },
  }
}
