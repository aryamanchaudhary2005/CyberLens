import { expect, test } from '@playwright/test'

test('login has labels, empty password, and visible focus', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  const password = page.getByLabel('Password')
  await expect(password).toHaveValue('')
  await password.focus()
  await expect(password).toBeFocused()
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeEnabled()
})
