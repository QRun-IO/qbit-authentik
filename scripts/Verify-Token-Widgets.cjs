/* Copyright 2026 Kingsrook, LLC. SPDX-License-Identifier: Apache-2.0 */
const path = require('node:path');
const { createRequire } = require('node:module');
const frontend = process.env.QBIT_REVIEW_FRONTEND || path.join(process.env.USERPROFILE, '.cache', 'qqq-authentik-access-ui');
const { chromium, expect } = createRequire(path.join(frontend, 'package.json'))('@playwright/test');

/** Send a reset email to synthetic Sam, then render the resulting token. */
async function main()
{
   const browser = await chromium.launch({ headless: true });
   try
   {
      const page = await browser.newPage();
      page.setDefaultTimeout(30000);
      await page.goto('http://127.0.0.1:18300/app/authentik_user');
      await page.getByText('review.sam', { exact: true }).first().click();
      await page.waitForURL(/\/authentik_user\/\d+\/?$/);
      const userURL = page.url();
      await page.getByRole('button', { name: 'Record actions menu', exact: true }).click();
      await page.getByRole('menuitem', { name: 'Send Password Reset Email', exact: true }).click();
      await page.getByRole('textbox', { name: 'Reason', exact: true }).fill('Local token widget regression verification');
      await page.getByRole('button', { name: 'Next', exact: true }).last().click();
      const review = page.getByRole('form', { name: 'Review', exact: true });
      await review.waitFor();
      await expect(review).toContainText('OK: 1');
      await page.getByRole('button', { name: 'Submit', exact: true }).click();
      const result = page.getByRole('form', { name: 'Result', exact: true });
      await result.waitFor();
      await expect(result).toContainText('OK: 1');
      await page.goto(userURL);
      await page.getByRole('tab', { name: 'Tokens and app passwords', exact: true }).click();
      await expect(page.getByRole('cell', { name: 'verification', exact: true }).first()).toBeVisible({ timeout: 30000 });
      await expect(page.getByRole('cell', { name: 'Owner permissions', exact: true }).first()).toBeVisible();
      await expect(page.getByText(/An error occurred loading widget content|Error executing query/)).toHaveCount(0);
      console.log('PASS: Tokens and app passwords renders a real password-reset token without a query error.');
   }
   finally
   {
      await browser.close();
   }
}
main().catch(error => { console.error(error.message.replace(/[a-f0-9]{32,}/g, '<identifier>')); process.exitCode = 1; });
