import { useEffect, useRef, useState } from 'react'

type ElementRef<T extends Element> = { current: T | null }

/** Data-saving and accessibility preferences both avoid decorative GPU work. */
export function useMotionConstraints(reduced: boolean) {
  const connection = (navigator as Navigator & { connection?: EventTarget & { saveData?: boolean } }).connection
  const [saveData, setSaveData] = useState(() => connection?.saveData === true)
  useEffect(() => {
    const update = () => setSaveData(connection?.saveData === true)
    connection?.addEventListener?.('change', update)
    update()
    return () => connection?.removeEventListener?.('change', update)
  }, [connection])
  return reduced || saveData
}

/** One playback gate for decorative CSS and canvas effects; never runs per frame. */
export function useDecorativeMotion<T extends Element>(ref: ElementRef<T>, reduced: boolean, paused = false) {
  const staticOnly = useMotionConstraints(reduced)
  const [visible, setVisible] = useState(() => document.visibilityState !== 'hidden')
  const [intersecting, setIntersecting] = useState(true)

  useEffect(() => {
    const updateVisibility = () => setVisible(document.visibilityState !== 'hidden')
    let observer: IntersectionObserver | undefined
    document.addEventListener('visibilitychange', updateVisibility)
    try {
      if (ref.current && 'IntersectionObserver' in window) {
        observer = new IntersectionObserver(([entry]) => setIntersecting(entry?.isIntersecting ?? true), { threshold: 0 })
        observer.observe(ref.current)
      }
    } catch { observer?.disconnect() }
    updateVisibility()
    return () => {
      document.removeEventListener('visibilitychange', updateVisibility)
      observer?.disconnect()
    }
  }, [ref])

  return { staticOnly, running: !staticOnly && !paused && visible && intersecting }
}

/** Keep component-level motion in sync with both app and operating-system preferences. */
export function useReducedMotionPreference() {
  const [reduced, setReduced] = useState(() => typeof window !== 'undefined' && (
    window.matchMedia('(prefers-reduced-motion: reduce)').matches ||
    document.documentElement.dataset.motion === 'reduced'
  ))

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)')
    const update = () => setReduced(media.matches || document.documentElement.dataset.motion === 'reduced')
    const observer = new MutationObserver(update)
    media.addEventListener?.('change', update)
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-motion'] })
    update()
    return () => { media.removeEventListener?.('change', update); observer.disconnect() }
  }, [])

  return reduced
}

/** A chart/ring entrance that runs once, then stays off for later data refreshes. */
export function useInitialMotion(duration = 460) {
  const reduced = useReducedMotionPreference()
  const [active, setActive] = useState(false)
  const played = useRef(false)

  useEffect(() => {
    if (played.current) return
    if (reduced) { played.current = true; setActive(false); return }
    setActive(true)
    const timer = window.setTimeout(() => { played.current = true; setActive(false) }, duration)
    return () => window.clearTimeout(timer)
  }, [duration, reduced])

  return active
}

/** Reveal visible workspace panels once when a route enters the page. */
export function useViewportReveals(
  pageRef: ElementRef<HTMLElement>,
  routeKey: string,
  reducedMotion: boolean,
  enabled: boolean,
) {
  useEffect(() => {
    const page = pageRef.current
    if (!enabled || !page || reducedMotion || !('IntersectionObserver' in window)) return

    const collections = '.table-wrap, .bento-table-wrap, .chart-motion-frame, .graph-canvas-scroll'
    const selector = '.panel, .bento-card, .finding-card, .remediation-record, .monitoring-card, .integration-card, .posture-metric-card, .attack-tactic, ' + collections
    let observer: IntersectionObserver | undefined
    let arrivals: MutationObserver | undefined
    let index = 0
    let failed = false
    const registered = new WeakSet<HTMLElement>()
    const styled = new Set<HTMLElement>()
    const cleanup = () => {
      observer?.disconnect()
      arrivals?.disconnect()
      styled.forEach((element) => element.style.removeProperty('--motion-reveal-delay'))
      styled.clear()
    }
    const register = (root: HTMLElement) => {
      if (failed) return
      const candidates = [...(root.matches(selector) ? [root] : []), ...root.querySelectorAll<HTMLElement>(selector)]
      try {
        for (const element of candidates) {
          const collection = element.matches(collections)
          if (registered.has(element) || (!collection && element.parentElement?.closest('.panel, .bento-card'))) continue
          registered.add(element)
          if (element.classList.contains('motion-revealed') || element.classList.contains('collection-revealed') || element.matches(':focus-within') || element.closest('.large-graph')) continue
          element.style.setProperty('--motion-reveal-delay', `${Math.min(index++ * 16, 96)}ms`)
          styled.add(element)
          observer?.observe(element)
        }
      } catch { failed = true; cleanup() }
    }
    try {
      observer = new IntersectionObserver((entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue
          const element = entry.target as HTMLElement
          observer?.unobserve(element)
          if (element.matches(':focus-within')) continue
          element.classList.add(element.matches(collections) ? 'collection-revealed' : 'motion-revealed')
        }
      }, { threshold: 0.08, rootMargin: '0px 0px -20px 0px' })

      register(page)
      // Async scorecards/results can arrive after the route effect. Observe only
      // new HTML subtrees; existing panels and polling updates never replay.
      if (!failed && 'MutationObserver' in window) {
        arrivals = new MutationObserver((records) => {
          for (const record of records) for (const node of record.addedNodes) {
            if (node instanceof HTMLElement) register(node)
          }
        })
        arrivals.observe(page, { childList: true, subtree: true })
      }
    } catch {
      cleanup()
      // The CSS starts fully visible; an unavailable observer only skips the reveal.
    }

    return cleanup
  }, [pageRef, routeKey, reducedMotion, enabled])
}

/** Same-section detail changes need a transition without remounting forms or tables. */
export function useSectionMotion(pageRef: ElementRef<HTMLElement>, view: string, detailKey: string, reducedMotion: boolean, enabled: boolean) {
  const previous = useRef({ view, detailKey })
  useEffect(() => {
    const old = previous.current
    previous.current = { view, detailKey }
    const page = pageRef.current
    if (!enabled || reducedMotion || !page || old.view !== view || old.detailKey === detailKey || !page.animate) return
    let animation: Animation | undefined
    try {
      const style = getComputedStyle(page)
      const duration = parseFloat(style.getPropertyValue('--motion-page')) || 220
      animation = page.animate([{ opacity: .9, transform: 'translateY(5px)' }, { opacity: 1, transform: 'none' }], {
        duration, easing: style.getPropertyValue('--ease-standard').trim() || 'ease-out',
      })
    } catch { /* Browser animation support must never gate content. */ }
    return () => animation?.cancel()
  }, [pageRef, view, detailKey, reducedMotion, enabled])
}

/** Add a restrained appearance to the sticky workspace header after scrolling. */
export function useStickyHeader(headerRef: ElementRef<HTMLElement>, enabled: boolean) {
  useEffect(() => {
    const header = headerRef.current
    if (!enabled || !header) return
    const update = () => header.classList.toggle('is-scrolled', window.scrollY > 8)
    update()
    window.addEventListener('scroll', update, { passive: true })
    return () => window.removeEventListener('scroll', update)
  }, [headerRef, enabled])
}
