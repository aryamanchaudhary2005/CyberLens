/** Original, deliberately simplified geographic silhouettes in longitude/latitude.
 * Decorative only: connections do not represent customers, traffic, or attacks.
 * Orthographic 3D projection uses Canvas2D, avoiding a GPU/framework dependency.
 */
type Point = [number, number]
type Vector = [number, number, number]
const land: Point[][] = [
  [[-168,66],[-150,71],[-130,70],[-112,74],[-94,72],[-82,63],[-61,55],[-53,48],[-65,44],[-77,34],[-81,25],[-89,30],[-97,24],[-87,16],[-78,9],[-84,9],[-99,18],[-109,24],[-117,32],[-124,42],[-130,54],[-145,59],[-168,60]],
  [[-73,59],[-49,59],[-22,70],[-28,82],[-49,84],[-65,76]],
  [[-81,12],[-70,11],[-60,6],[-50,1],[-35,-6],[-39,-20],[-48,-28],[-54,-39],[-66,-55],[-72,-51],[-75,-32],[-80,-8]],
  [[-17,35],[-3,37],[10,37],[25,32],[33,31],[43,12],[51,12],[43,1],[40,-13],[32,-28],[20,-35],[12,-26],[9,-4],[1,5],[-10,5],[-17,15]],
  [[-10,36],[-10,44],[-1,49],[8,54],[5,59],[17,71],[30,71],[34,61],[44,67],[67,73],[100,77],[129,72],[160,70],[179,65],[170,53],[151,59],[142,48],[134,43],[129,34],[121,30],[119,22],[108,18],[110,5],[103,1],[98,14],[88,21],[80,8],[73,18],[67,25],[57,25],[53,16],[44,12],[35,30],[28,40],[24,35],[19,41],[15,38],[12,45],[3,43]],
  [[112,-11],[128,-12],[137,-11],[145,-17],[153,-28],[145,-39],[131,-32],[116,-35],[113,-24]],
  [[47,-13],[51,-16],[49,-25],[44,-25],[44,-18]],
  [[-9,50],[-5,50],[1,53],[-3,59],[-7,58]],
  [[130,31],[134,34],[140,40],[145,44],[143,36],[136,33]],
  [[95,5],[105,-5],[114,-7],[119,-5],[111,2],[108,7],[101,3]],
  [[130,-3],[141,-3],[151,-8],[142,-10]],
  [[166,-35],[174,-41],[178,-46],[170,-45]],
]
const rad = Math.PI / 180
function vector([lon, lat]: Point): Vector {
  return [Math.cos(lat * rad) * Math.sin(lon * rad), Math.sin(lat * rad), Math.cos(lat * rad) * Math.cos(lon * rad)]
}
function inside([x, y]: Point, polygon: Point[]) {
  let hit = false
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i], [xj, yj] = polygon[j]
    if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) hit = !hit
  }
  return hit
}
const dots: Vector[] = []
for (let lat = -56; lat <= 82; lat += 2) {
  for (let lon = -180; lon < 180; lon += 2 / Math.cos(lat * rad)) {
    if (land.some((polygon) => inside([lon, lat], polygon))) dots.push(vector([lon, lat]))
  }
}
const connections: [Point, Point][] = [
  [[-74,41],[-1,51]], [[-1,51],[77,28]], [[2,49],[18,-34]], [[77,28],[139,36]], [[103,1],[151,-34]],
]
const arcs = connections.map(([start, end]) => {
  const a = vector(start), b = vector(end)
  return Array.from({ length: 65 }, (_, index): Vector => {
    const t = index / 64, height = 1 + .18 * Math.sin(t * Math.PI)
    const v = a.map((value, axis) => value * (1 - t) + b[axis] * t)
    const length = Math.hypot(...v)
    return v.map((value) => value / length * height) as Vector
  })
})

export function createDigitalEarth(canvas: HTMLCanvasElement) {
  const context = canvas.getContext('2d', { alpha: true })
  if (!context) throw new Error('Canvas unavailable')
  const ctx = context
  let frame = 0, previous = 0, elapsed = 0, playing = false, disposed = false
  let size = 640, drawCount = 0
  function draw() {
    const angle = elapsed / 120 * Math.PI * 2 - .30
    const sin = Math.sin(angle), cos = Math.cos(angle)
    function project([x, y, z]: Vector): Vector {
      const rotatedX = x * cos + z * sin, rotatedZ = z * cos - x * sin
      // Fixed axial tilt; only the Earth rotates, not the entire image plane.
      return [320 + (rotatedX * .985 + y * .174) * 232, 320 + (rotatedX * .174 - y * .985) * 232, rotatedZ]
    }
    ctx.setTransform(size / 640, 0, 0, size / 640, 0, 0)
    ctx.clearRect(0, 0, 640, 640)
    const halo = ctx.createRadialGradient(320, 320, 218, 320, 320, 290)
    halo.addColorStop(0, '#7469ff60'); halo.addColorStop(.35, '#5042e51c'); halo.addColorStop(1, '#5042e500')
    ctx.fillStyle = halo; ctx.fillRect(0, 0, 640, 640)
    const ocean = ctx.createRadialGradient(230, 210, 20, 330, 340, 260)
    ocean.addColorStop(0, '#192c55'); ocean.addColorStop(.65, '#0a152c'); ocean.addColorStop(1, '#030811')
    ctx.beginPath(); ctx.arc(320, 320, 232, 0, Math.PI * 2); ctx.fillStyle = ocean; ctx.fill()
    function line(points: Vector[], color: string, width: number) {
      ctx.beginPath(); let connected = false
      for (const v of points) {
        const [x, y, z] = project(v)
        if (z < .015) { connected = false; continue }
        if (connected) ctx.lineTo(x, y); else ctx.moveTo(x, y)
        connected = true
      }
      ctx.strokeStyle = color; ctx.lineWidth = width; ctx.stroke()
    }
    for (let lat = -60; lat <= 60; lat += 30) line(Array.from({ length: 121 }, (_, i) => vector([i * 3 - 180, lat])), '#738aff26', .65)
    for (let lon = -180; lon < 180; lon += 30) line(Array.from({ length: 61 }, (_, i) => vector([lon, i * 3 - 90])), '#738aff26', .65)
    for (const dot of dots) {
      const [x, y, z] = project(dot)
      if (z <= 0) continue
      ctx.globalAlpha = .3 + .7 * z
      ctx.fillStyle = '#a9a1ff'
      ctx.beginPath(); ctx.arc(x, y, .65 + .65 * z, 0, Math.PI * 2); ctx.fill()
    }
    ctx.globalAlpha = 1
    for (let i = 0; i < arcs.length; i++) {
      const arc = arcs[i]
      line(arc, '#9484ff9c', 1)
      const [x, y, z] = project(arc[Math.floor(((elapsed / 5 + i * .19) % 1) * 64)])
      if (z > .015) {
        const glow = ctx.createRadialGradient(x, y, 0, x, y, 9)
        glow.addColorStop(0, '#e5ddff'); glow.addColorStop(.2, '#ac96ff'); glow.addColorStop(1, '#8870ff00')
        ctx.fillStyle = glow; ctx.fillRect(x - 9, y - 9, 18, 18)
      }
      for (const v of [arc[0], arc[64]]) {
        const [nx, ny, nz] = project(v)
        if (nz > .015) { ctx.beginPath(); ctx.arc(nx, ny, 2.3, 0, Math.PI * 2); ctx.fillStyle = '#c4b5ff'; ctx.fill() }
      }
    }
    ctx.beginPath(); ctx.arc(320, 320, 232, 0, Math.PI * 2); ctx.strokeStyle = '#a99aff7a'; ctx.lineWidth = 1.2; ctx.stroke()
    canvas.dataset.rotation = angle.toFixed(6)
    canvas.dataset.frames = String(++drawCount)
  }
  function resize() {
    size = Math.max(1, Math.round(Math.min(960, canvas.getBoundingClientRect().width * Math.min(window.devicePixelRatio || 1, 1.5))))
    canvas.width = canvas.height = size
    draw()
  }
  function tick(now: number) {
    if (!playing || disposed) return
    if (!previous) previous = now
    if (now - previous >= 1000 / 30) {
      elapsed += Math.min((now - previous) / 1000, .1)
      previous = now; draw()
    }
    frame = requestAnimationFrame(tick)
  }
  let observer: ResizeObserver | undefined
  try { if ('ResizeObserver' in window) { observer = new ResizeObserver(resize); observer.observe(canvas) } } catch { observer?.disconnect() }
  window.addEventListener('resize', resize)
  resize()
  return {
    setRunning(value: boolean) {
      if (disposed || value === playing) return
      playing = value; previous = 0
      cancelAnimationFrame(frame)
      if (playing) frame = requestAnimationFrame(tick)
    },
    dispose() {
      disposed = true; playing = false; cancelAnimationFrame(frame)
      observer?.disconnect(); window.removeEventListener('resize', resize)
      ctx.clearRect(0, 0, canvas.width, canvas.height)
    },
  }
}
