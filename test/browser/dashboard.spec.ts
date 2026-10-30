import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
const tokens = () => JSON.parse(readFileSync('test-results/tokens.json', 'utf8'));
test('dashboard workflow, safe rendering, and mobile layout', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await page.getByLabel('Access token', { exact: true }).fill(tokens().operator);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#checks')).toHaveText('18/18');
  await page.getByRole('button', { name: 'Replay scenario', exact: false }).click();
  await expect(page.locator('#finding-count')).toHaveText('4');
  await expect(page.locator('#timeline')).toContainText('privilege.grant');
  await page.locator('#finding-list button').nth(1).click();
  await expect(page.locator('#timeline')).toContainText('credential.create');
  await page.locator('#scenario').selectOption('aws-benign-read');
  await page.getByRole('button', { name: 'Replay scenario', exact: false }).click();
  await expect(page.locator('#finding-count')).toHaveText('0');
  await expect(page.locator('#finding-list')).toContainText('No findings');
  const exported = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSON', exact: false }).click();
  expect((await exported).suggestedFilename()).toBe('investigation.json');
  const events = JSON.parse(readFileSync('fixtures/aws-attack.json', 'utf8'));
  for (const e of events) e.record.userIdentity.principalId = '<img src=x onerror=alert(1)>';
  await page.locator('summary').click();
  await page.locator('#event-file').setInputFiles({
    name: 'synthetic.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(events)),
  });
  await page.getByRole('button', { name: 'Validate and replay', exact: true }).click();
  await expect(page.locator('#finding-list')).toContainText('<img src=x onerror=alert(1)>');
  await expect(page.locator('img')).toHaveCount(0);
  await page.locator('#scenario').selectOption('aws-identity-chain');
  await page.getByRole('button', { name: 'Replay scenario', exact: false }).click();
  await expect(page.locator('#finding-count')).toHaveText('4');
  await page.getByLabel('Access token', { exact: true }).fill('');
  await page.screenshot({ path: 'test-results/dashboard-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator('h1')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: 'test-results/dashboard-mobile.png', fullPage: true });
  expect(errors).toEqual([]);
});
