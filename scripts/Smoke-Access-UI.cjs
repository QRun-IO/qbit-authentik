/* Copyright 2026 Kingsrook, LLC. Licensed under the Apache License, Version 2.0. */

/**
 * Live local-review smoke test. Uses the actual QQQ backend, without API mocks.
 * Requires the access UI's installed @playwright/test and Chromium browser.
 * Opens the synthetic review user, filters the permission matrix, toggles a
 * draft grant and cancels. Never executes a permission change.
 * Run: node scripts/Smoke-Access-UI.cjs
 */
const path = require('node:path');
const { createRequire } = require('node:module');
const frontend = process.env.QBIT_REVIEW_FRONTEND || path.join(process.env.USERPROFILE, '.cache', 'qqq-authentik-access-ui');
const { chromium, expect } = createRequire(path.join(frontend, 'package.json'))('@playwright/test');
const baseURL = process.env.QBIT_REVIEW_UI_URL || 'http://127.0.0.1:18301';

/** Check rendered controls and draft selection without persisting changes. */
async function main()
{
   const browser = await chromium.launch({ headless: true });
   try
   {
      const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
      page.setDefaultTimeout(20000);
      page.setDefaultNavigationTimeout(20000);
      await page.goto(baseURL + '/app/authentik_user');
      await page.getByText('review.sam', { exact: true }).first().click();
      await page.waitForURL(/\/authentik_user\/\d+\/?$/);
      await page.getByRole('button', { name: 'Record actions menu', exact: true }).click();
      await page.getByText('Edit User Permissions', { exact: true }).click();
      const matrix = page.locator('[data-qqq-id="access-permission-matrix"]');
      await expect(matrix).toBeVisible();
      await expect(matrix.getByRole('checkbox').first()).toBeVisible();
      await expect(matrix.getByRole('alert')).toHaveCount(0);
      await matrix.getByLabel('Search permissions or resources', { exact: true }).fill('review_document');
      const read = matrix.getByRole('checkbox', { name: 'review_document.read', exact: true });
      await expect(read).toBeEnabled();
      const wasChecked = await read.isChecked();
      await read.setChecked(!wasChecked);
      await expect(read).toBeChecked({ checked: !wasChecked });
      await page.screenshot({ path: 'target/release-access-ui-catalog.png', fullPage: true });
      await matrix.getByLabel('Show', { exact: true }).selectOption('selected');
      if(!wasChecked)
      {
         await expect(matrix.getByRole('checkbox', { name: 'review_document.read', exact: true })).toBeChecked();
      }
      await matrix.getByLabel('Show', { exact: true }).selectOption('inherited');
      await matrix.getByLabel('Search permissions or resources', { exact: true }).fill('');
      await expect(matrix.getByText(/authentik\.users\.read\.hasAccess.*Review Readers/)).toBeVisible();
      await expect(matrix.getByText('Inherited grants must be changed at their source. Policy grants use Edit Policy.')).toBeVisible();
      await page.screenshot({ path: 'target/release-access-ui-smoke.png', fullPage: true });
      await page.getByRole('button', { name: 'Cancel', exact: true }).click();
      console.log('PASS: live permission catalog, resource search, draft checkbox, selection view, inherited-source view and cancel. No changes executed.');
   }
   finally
   {
      await browser.close();
   }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
