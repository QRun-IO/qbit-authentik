/* Copyright 2026 Kingsrook, LLC. Licensed under the Apache License, Version 2.0. */
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { chromium, expect } = createRequire(path.join(process.env.USERPROFILE, '.cache', 'qqq-authentik-access-ui', 'package.json'))('@playwright/test');
const baseURL = 'http://127.0.0.1:18300';
const reason = 'UI acceptance ' + Date.now();

/** Read synthetic provider state independently of the QQQ UI. Never print credentials. */
async function provider(resource)
{
   const log = fs.readFileSync('target/review-server.log', 'utf8');
   const root = log.match(/REVIEW AUTHENTIK (http:\/\/127\.0\.0\.1:\d+)/)?.[1];
   if(!root) throw new Error('No owned review Authentik URL');
   const source = fs.readFileSync('src/test/java/com/kingsrook/qbits/authentik/contract/AuthentikTestStack.java', 'utf8');
   const token = source.match(/BOOTSTRAP_TOKEN\s*=\s*"([^"]+)"/)?.[1];
   const response = await fetch(root + '/api/v3/' + resource, { headers: { Authorization: 'Bearer ' + token } });
   if(!response.ok) throw new Error('Provider read failed: ' + response.status);
   return response.json();
}

/** Open the real record action; all mutations go through rendered UI controls. */
async function action(page, name)
{
   await page.goto(baseURL + '/app/authentik_user');
   await page.getByText('review.sam', { exact: true }).first().click();
   await page.waitForURL(/\/authentik_user\/\d+\/?$/);
   await page.getByRole('button', { name: 'Record actions menu', exact: true }).click();
   await page.getByRole('menuitem', { name, exact: true }).click();
}

/** Require valid review and successful execution before checking provider state. */
async function submit(page)
{
   await page.getByRole('textbox', { name: 'Reason', exact: true }).fill(reason);
   await page.getByRole('button', { name: 'Next', exact: true }).last().click();
   await expect(page.getByRole('form', { name: 'Review', exact: true })).toContainText('OK: 1');
   await page.getByRole('button', { name: 'Submit', exact: true }).click();
   await expect(page.getByRole('form', { name: 'Result', exact: true })).toContainText('OK: 1');
}

/** Exercise direct grant addition/removal, role addition/removal and durable audit. */
async function main()
{
   const users = await provider('core/users/?username=review.sam');
   expect(users.results).toHaveLength(1);
   const pk = users.results[0].pk;
   const roles = await provider('core/groups/?name=Review%20Viewer&include_users=true');
   expect(roles.results).toHaveLength(1);
   const rolePk = roles.results[0].pk;
   expect(roles.results[0].users).not.toContain(pk);
   const browser = await chromium.launch({ headless: true });
   try
   {
      const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
      page.setDefaultTimeout(20000);
      page.setDefaultNavigationTimeout(20000);
      await action(page, 'Edit User Permissions');
      const initialBox = page.getByRole('checkbox', { name: 'review_document.read', exact: true });
      await expect(initialBox).toBeVisible();
      const initialGrant = await initialBox.isChecked();
      await page.getByRole('button', { name: 'Cancel', exact: true }).click();
      for(const selected of [!initialGrant, initialGrant])
      {
         await action(page, 'Edit User Permissions');
         const box = page.getByRole('checkbox', { name: 'review_document.read', exact: true });
         await expect(box).toBeVisible();
         if(await box.isChecked() !== selected)
         {
            await box.setChecked(selected);
            await submit(page);
         }
         else await page.getByRole('button', { name: 'Cancel', exact: true }).click();
         const groups = await provider('core/groups/?page_size=100&include_users=true');
         expect(groups.pagination.next).toBeFalsy();
         const direct = groups.results.filter(group => group.attributes?.['qqq.io/user-access-owner'] === 'kof22-admin:' + pk);
         expect(direct.length).toBeLessThanOrEqual(1);
         expect(direct.some(group => group.attributes['qqq.io/permissions']?.includes('review_document.read'))).toBe(selected);
         if(direct.length) expect(direct[0].users).toEqual([pk]);
      }
      for(const add of [true, false])
      {
         await action(page, add ? 'Add To Group Or Role' : 'Remove From Group Or Role');
         await page.getByRole('combobox', { name: 'Group', exact: true }).click();
         await page.getByRole('textbox', { name: 'Search Group options', exact: true }).fill('Review Viewer');
         await page.getByRole('option', { name: 'Review Viewer', exact: true }).click();
         await submit(page);
         const group = await provider('core/groups/' + rolePk + '/?include_users=true');
         expect(group.users.includes(pk)).toBe(add);
      }
      const response = await page.request.post(baseURL + '/qqq/v1/table/authentik_admin_action/query?limit=100', { data: {} });
      expect(response.ok()).toBeTruthy();
      const audit = (await response.json()).records.map(record => record.values).filter(record => record.reason === reason);
      for(const name of ['EDIT_USER_PERMISSIONS', 'ADD_MEMBER', 'REMOVE_MEMBER'])
      {
         expect(audit.some(record => record.actionName === name && record.status === 'SUCCEEDED')).toBeTruthy();
      }
      await page.screenshot({ path: 'target/review-access-writes.png', fullPage: true });
      console.log('PASS: rendered direct grant add/remove, role add/remove, independent Authentik state and successful SQL audits. Synthetic user restored.');
   }
   finally { await browser.close(); }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
