import { useEffect, useRef } from 'react'
import { useDecorativeMotion } from './motion'
import './gradient-orb-background.css'

type GradientOrbBackgroundProps = {
  reducedMotion: boolean
  paused?: boolean
}

const vertexShader = `
  attribute vec2 position;
  varying vec2 vUv;
  void main() {
    vUv = position * 0.5 + 0.5;
    gl_Position = vec4(position, 0.0, 1.0);
  }
`

// Adapted from the supplied GradientOrb shader. Its movement is slowed for a
// dashboard backdrop and its colors follow the CyberLens indigo palette.
const fragmentShader = `
  precision highp float;
  uniform float iTime;
  uniform vec3 iResolution;
  uniform float rot;
  varying vec2 vUv;

  vec3 hash33(vec3 p3) {
    p3 = fract(p3 * vec3(0.1031, 0.11369, 0.13787));
    p3 += dot(p3, p3.yxz + 19.19);
    return -1.0 + 2.0 * fract(vec3(p3.x + p3.y, p3.x + p3.z, p3.y + p3.z) * p3.zyx);
  }

  float snoise3(vec3 p) {
    const float K1 = 0.333333333;
    const float K2 = 0.166666667;
    vec3 i = floor(p + (p.x + p.y + p.z) * K1);
    vec3 d0 = p - (i - (i.x + i.y + i.z) * K2);
    vec3 e = step(vec3(0.0), d0 - d0.yzx);
    vec3 i1 = e * (1.0 - e.zxy);
    vec3 i2 = 1.0 - e.zxy * (1.0 - e);
    vec3 d1 = d0 - (i1 - K2);
    vec3 d2 = d0 - (i2 - K1);
    vec3 d3 = d0 - 0.5;
    vec4 h = max(0.6 - vec4(dot(d0,d0), dot(d1,d1), dot(d2,d2), dot(d3,d3)), 0.0);
    vec4 n = h*h*h*h * vec4(
      dot(d0, hash33(i)), dot(d1, hash33(i + i1)),
      dot(d2, hash33(i + i2)), dot(d3, hash33(i + 1.0))
    );
    return dot(vec4(31.316), n);
  }

  float light1(float intensity, float attenuation, float dist) {
    return intensity / (1.0 + dist * attenuation);
  }
  float light2(float intensity, float attenuation, float dist) {
    return intensity / (1.0 + dist * dist * attenuation);
  }

  vec4 extractAlpha(vec3 colorIn) {
    float a = max(max(colorIn.r, colorIn.g), colorIn.b);
    return vec4(colorIn.rgb / (a + 1e-5), a);
  }

  vec4 draw(vec2 uv) {
    vec3 color0 = vec3(0.427, 0.365, 0.965);
    vec3 color1 = vec3(0.545, 0.486, 1.0);
    vec3 color2 = vec3(0.686, 0.651, 1.0);
    vec3 color3 = vec3(0.0);
    float len = length(uv);
    float invLen = len > 0.0 ? 1.0 / len : 0.0;
    float pulse = sin(iTime * 0.16) * 0.012;
    float n0 = snoise3(vec3(uv * 0.65, iTime * 0.12)) * 0.5 + 0.5;
    float r0 = mix(mix(0.1 + pulse, 1.0, 0.4), mix(0.1 + pulse, 1.0, 0.6), n0);
    float d0 = distance(uv, (r0 * invLen) * uv);
    float v0 = light1(1.0, 10.0, d0);
    v0 *= 1.0 - smoothstep(r0, r0 * 1.05, len);
    float cl = cos(atan(uv.y, uv.x) + iTime * 0.05) * 0.5 + 0.5;
    float a = iTime * -0.35;
    vec2 pos = vec2(cos(a), sin(a)) * r0;
    float d = distance(uv, pos);
    float v1 = light2(1.5, 5.0, d) * light1(1.0, 50.0, d0);
    float edge = mix(0.1, 1.0, n0 * 0.5);
    float v2 = 1.0 - smoothstep(edge, 1.0, len);
    float v3 = smoothstep(0.1, mix(0.1, 1.0, 0.5), len);
    vec3 col = mix(color1, color2, cl);
    col = mix(col, color0, n0);
    col = mix(color3, col, v0);
    col = clamp((col + v1) * v2 * v3, 0.0, 1.0);
    return extractAlpha(col);
  }

  void main() {
    vec2 center = iResolution.xy * 0.5;
    float size = min(iResolution.x, iResolution.y);
    vec2 uv = (vUv * iResolution.xy - center) / size * 2.0;
    float s = sin(rot);
    float c = cos(rot);
    uv = vec2(c * uv.x - s * uv.y, s * uv.x + c * uv.y);
    vec4 col = draw(uv);
    gl_FragColor = vec4(col.rgb * col.a, col.a);
  }
`

function createProgram(gl: WebGLRenderingContext): WebGLProgram | null {
  const compile = (type: number, source: string) => {
    const shader = gl.createShader(type)
    if (!shader) return null
    gl.shaderSource(shader, source)
    gl.compileShader(shader)
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      gl.deleteShader(shader)
      return null
    }
    return shader
  }

  const vertex = compile(gl.VERTEX_SHADER, vertexShader)
  const fragment = compile(gl.FRAGMENT_SHADER, fragmentShader)
  if (!vertex || !fragment) {
    if (vertex) gl.deleteShader(vertex)
    if (fragment) gl.deleteShader(fragment)
    return null
  }

  const program = gl.createProgram()
  if (!program) {
    gl.deleteShader(vertex)
    gl.deleteShader(fragment)
    return null
  }
  gl.attachShader(program, vertex)
  gl.attachShader(program, fragment)
  gl.linkProgram(program)
  gl.deleteShader(vertex)
  gl.deleteShader(fragment)
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    gl.deleteProgram(program)
    return null
  }
  return program
}

export function GradientOrbBackground({ reducedMotion, paused = false }: GradientOrbBackgroundProps) {
  const hostRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const { running: shouldPlay, staticOnly } = useDecorativeMotion(hostRef, reducedMotion, paused)
  const playback = useRef(shouldPlay)
  const sync = useRef<(() => void) | null>(null)

  useEffect(() => { playback.current = shouldPlay; sync.current?.() }, [shouldPlay])

  useEffect(() => {
    const host = hostRef.current
    const canvas = canvasRef.current
    if (!host || !canvas || staticOnly) {
      if (host) host.dataset.renderer = 'fallback'
      return
    }

    let gl: WebGLRenderingContext | null = null
    let program: WebGLProgram | null = null
    let buffer: WebGLBuffer | null = null
    let frame = 0
    let running = false
    let previousTime = 0
    let previousFrame = 0
    let elapsed = 0
    let lost = false
    let resizeObserver: ResizeObserver | null = null
    let onContextLost: ((event: Event) => void) | null = null
    let onResize: (() => void) | null = null

    try {
      gl = canvas.getContext('webgl', {
        alpha: true,
        antialias: false,
        depth: false,
        powerPreference: 'low-power',
        premultipliedAlpha: true,
        preserveDrawingBuffer: false,
        stencil: false,
      })
      if (!gl) return
      program = createProgram(gl)
      buffer = gl.createBuffer()
      if (!program || !buffer) throw new Error('Orb renderer unavailable')

      gl.bindBuffer(gl.ARRAY_BUFFER, buffer)
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW)
      gl.useProgram(program)
      const position = gl.getAttribLocation(program, 'position')
      gl.enableVertexAttribArray(position)
      gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0)
      gl.clearColor(0, 0, 0, 0)

      const timeLocation = gl.getUniformLocation(program, 'iTime')
      const resolutionLocation = gl.getUniformLocation(program, 'iResolution')
      const rotationLocation = gl.getUniformLocation(program, 'rot')
      if (!timeLocation || !resolutionLocation || !rotationLocation) throw new Error('Orb shader uniforms unavailable')
      host.dataset.renderer = 'webgl'

      const resize = () => {
        if (!gl || lost) return
        const rect = host.getBoundingClientRect()
        // The backdrop is intentionally soft; rendering below device resolution
        // keeps the full-screen shader inexpensive on high-density displays.
        const pixelRatio = Math.min(.8, 1100 / Math.max(rect.width, 1), 700 / Math.max(rect.height, 1))
        const width = Math.max(1, Math.round(rect.width * pixelRatio))
        const height = Math.max(1, Math.round(rect.height * pixelRatio))
        if (canvas.width !== width || canvas.height !== height) {
          canvas.width = width
          canvas.height = height
          gl.viewport(0, 0, width, height)
        }
        gl.uniform3f(resolutionLocation, width, height, width / height)
      }

      const draw = (now: number) => {
        if (!gl || !program || !running || lost) return
        if (previousFrame && now - previousFrame < 1000 / 30) {
          frame = window.requestAnimationFrame(draw)
          return
        }
        previousFrame = now
        if (previousTime) elapsed += Math.min((now - previousTime) / 1000, 0.1)
        previousTime = now
        gl.useProgram(program)
        // Pass actual elapsed seconds. The shader already controls its own
        // restrained speed; applying another multiplier made it look static.
        gl.uniform1f(timeLocation, elapsed)
        gl.uniform1f(rotationLocation, elapsed * 0.055)
        gl.clear(gl.COLOR_BUFFER_BIT)
        gl.drawArrays(gl.TRIANGLES, 0, 3)
        frame = window.requestAnimationFrame(draw)
      }

      const syncPlayback = () => {
        const shouldRun = playback.current && !lost
        if (shouldRun && !running) {
          running = true
          previousTime = 0
          previousFrame = 0
          frame = window.requestAnimationFrame(draw)
        } else if (!shouldRun && running) {
          running = false
          window.cancelAnimationFrame(frame)
        }
      }

      sync.current = syncPlayback
      onContextLost = (event: Event) => {
        event.preventDefault()
        lost = true
        host.dataset.renderer = 'fallback'
        syncPlayback()
      }
      canvas.addEventListener('webglcontextlost', onContextLost)
      resizeObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(resize) : null
      resizeObserver?.observe(host)
      onResize = resize
      if (!resizeObserver) window.addEventListener('resize', resize)
      resize()
      syncPlayback()

      return () => {
        running = false
        sync.current = null
        window.cancelAnimationFrame(frame)
        resizeObserver?.disconnect()
        if (!resizeObserver && onResize) window.removeEventListener('resize', onResize)
        if (onContextLost) canvas.removeEventListener('webglcontextlost', onContextLost)
        if (gl && buffer) gl.deleteBuffer(buffer)
        if (gl && program) gl.deleteProgram(program)
      }
    } catch {
      // The CSS gradient remains visible when WebGL or shader setup is unavailable.
      host.dataset.renderer = 'fallback'
      sync.current = null
      window.cancelAnimationFrame(frame)
      resizeObserver?.disconnect()
      if (onResize) window.removeEventListener('resize', onResize)
      if (onContextLost) canvas.removeEventListener('webglcontextlost', onContextLost)
      if (gl && buffer) gl.deleteBuffer(buffer)
      if (gl && program) gl.deleteProgram(program)
      return
    }
  }, [staticOnly])

  return <div ref={hostRef} className="overview-gradient-orb" aria-hidden="true" data-motion={staticOnly ? 'reduced' : 'full'} data-playback={staticOnly ? 'static' : shouldPlay ? 'running' : 'paused'} data-renderer="fallback" data-testid="overview-gradient-orb">
    <canvas ref={canvasRef} className="overview-gradient-orb__canvas" />
  </div>
}
