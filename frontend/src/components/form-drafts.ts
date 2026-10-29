import { useEffect } from 'react'

type DraftControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
type FormDraft = { value: string; checked?: boolean }

const drafts = new Map<string, FormDraft>()
const submittedForms = new Set<string>()
const unsafeFieldName = /(password|token|secret|credential|api.?key|private.?key)/i

function controlsFor(form: HTMLFormElement): DraftControl[] {
  return Array.from(form.querySelectorAll<DraftControl>('input, select, textarea'))
}

function safeControl(control: DraftControl): boolean {
  if (control instanceof HTMLInputElement && ['password', 'hidden', 'file', 'submit', 'button', 'reset'].includes(control.type)) return false
  const labels = control.labels ? Array.from(control.labels, (label) => label.textContent ?? '').join(' ') : ''
  return !unsafeFieldName.test(`${control.name} ${control.id} ${control.getAttribute('aria-label') ?? ''} ${control.getAttribute('autocomplete') ?? ''} ${labels}`)
}

function formIdentity(form: HTMLFormElement, page: HTMLElement): string | null {
  const forms = Array.from(page.querySelectorAll('form'))
  const index = forms.indexOf(form)
  if (index < 0) return null
  return `${window.location.hash || '#/'}:${page.dataset.pageView ?? 'workspace'}:${index}`
}

function controlIdentity(control: DraftControl): { form: HTMLFormElement; key: string; prefix: string } | null {
  const page = control.closest<HTMLElement>('.page-transition')
  const form = control.form
  if (!page || !form || !safeControl(control)) return null
  const prefix = formIdentity(form, page)
  const index = controlsFor(form).indexOf(control)
  if (!prefix || index < 0) return null
  return { form, prefix, key: `${prefix}:${index}` }
}

function readDraft(control: DraftControl): FormDraft {
  if (control instanceof HTMLInputElement && ['checkbox', 'radio'].includes(control.type)) {
    return { value: control.value, checked: control.checked }
  }
  return { value: control.value }
}

function writeDraft(control: DraftControl, draft: FormDraft) {
  if (control instanceof HTMLInputElement && ['checkbox', 'radio'].includes(control.type)) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set
    setter?.call(control, Boolean(draft.checked))
  } else {
    const prototype = control instanceof HTMLInputElement ? HTMLInputElement.prototype
      : control instanceof HTMLSelectElement ? HTMLSelectElement.prototype
        : HTMLTextAreaElement.prototype
    Object.getOwnPropertyDescriptor(prototype, 'value')?.set?.call(control, draft.value)
  }
  control.dispatchEvent(new Event(control instanceof HTMLSelectElement || (control instanceof HTMLInputElement && ['checkbox', 'radio'].includes(control.type)) ? 'change' : 'input', { bubbles: true }))
}

/** Keep unsent non-secret form drafts in memory while analysts move between routes. */
export function useRouteFormDrafts(enabled: boolean, routeContext: string) {
  useEffect(() => {
    if (!enabled) return
    const remember = (event: Event) => {
      const control = event.target
      if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement)) return
      const identity = controlIdentity(control)
      if (identity) drafts.set(identity.key, readDraft(control))
    }
    const noteSubmit = (event: Event) => {
      const form = event.target
      if (!(form instanceof HTMLFormElement)) return
      const page = form.closest<HTMLElement>('.page-transition')
      const identity = page && formIdentity(form, page)
      if (identity) submittedForms.add(identity)
    }
    document.addEventListener('input', remember, true)
    document.addEventListener('change', remember, true)
    document.addEventListener('submit', noteSubmit, true)
    return () => {
      document.removeEventListener('input', remember, true)
      document.removeEventListener('change', remember, true)
      document.removeEventListener('submit', noteSubmit, true)
    }
  }, [enabled])

  useEffect(() => {
    if (!enabled) return
    let frame = 0
    frame = window.requestAnimationFrame(() => {
      const page = document.querySelector<HTMLElement>('.page-transition')
      if (!page) return
      for (const form of Array.from(page.querySelectorAll('form'))) {
        for (const control of controlsFor(form)) {
          if (control.matches(':focus')) continue
          const identity = controlIdentity(control)
          const saved = identity && drafts.get(identity.key)
          if (identity && saved) writeDraft(control, saved)
        }
      }
    })
    return () => window.cancelAnimationFrame(frame)
  }, [enabled, routeContext])
}

/** Remove only submitted form drafts after a successful action; failures keep them available. */
export function settleSubmittedFormDrafts(success: boolean) {
  if (success) {
    for (const prefix of submittedForms) {
      for (const key of drafts.keys()) if (key.startsWith(`${prefix}:`)) drafts.delete(key)
    }
  }
  submittedForms.clear()
}
