/* Copyright 2026 Kingsrook, LLC. Licensed under the Apache License, Version 2.0. */
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { chromium, expect } = createRequire(path.join(process.env.USERPROFILE, '.cache', 'qqq-authentik-access-ui', 'package.json'))('@playwright/test');
const baseURL = 'http://127.0.0.1:18300';
const reason = 'Group inheritance UI acceptance ' + Date.now();

/** Read real provider state independently; all mutations use rendered controls. */
async function provider(resource)
{
   const root = fs.readFileSync('target/review-server.log', 'utf8').match(/REVIEW AUTHENTIK (http:\/\/127\.0\.0\.1:\d+)/)?.[1];
   if(!root) throw new Error('Review provider not ready');
   const source = fs.readFileSync('src/test/java/com/kingsrook/qbits/authentik/contract/AuthentikTestStack.java', 'utf8');
   const token = source.match(/BOOTSTRAP_TOKEN\s*=\s*"([^"]+)"/)[1];
   const response = await fetch(root + '/api/v3/' + resource, { headers: { Authorization: 'Bearer ' + token } });
   if(!response.ok) throw new Error('Provider read failed: ' + response.status);
   return response.json();
}

/** Open the selected record's named action. */
async function action(page, table, record, name)
{
   await page.goto(baseURL + '/app/' + table);
   await page.getByText(record, { exact: true }).first().click();
   await page.getByRole('button', { name: 'Record actions menu', exact: true }).click();
   await page.getByRole('menuitem', { name, exact: true }).click();
}

/** Validate the dry-run and successful result. */
async function submit(page)
{
   await page.getByRole('textbox', { name: 'Reason', exact: true }).fill(reason);
   await page.getByRole('button', { name: 'Next', exact: true }).last().click();
   await expect(page.getByRole('form', { name: 'Review', exact: true })).toContainText('OK: 1');
   await page.getByRole('button', { name: 'Submit', exact: true }).click();
   await expect(page.getByRole('form', { name: 'Result', exact: true })).toContainText('OK: 1');
}

/** Verify role grants, group parents, inherited user access and removals. */
async function main()
{
   const readers = (await provider('core/groups/?name=Review%20Readers&include_parents=true')).results;
   const editors = (await provider('core/groups/?name=Review%20Editor')).results;
   expect(readers).toHaveLength(1);
   expect(editors).toHaveLength(1);
   const reader = readers[0];
   const editor = editors[0];
   expect(reader.parents_obj || []).toHaveLength(0);
   expect(editor.attributes['qqq.io/permissions']).not.toContain('review_document.delete');
   const browser = await chromium.launch({ headless: true });
   try
   {
      const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
      page.setDefaultTimeout(20000);
      page.setDefaultNavigationTimeout(20000);
      for(const selected of [true, false])
      {
         await action(page, 'authentik_group', 'Review Editor', 'Edit Permissions And App Access');
         await page.getByRole('checkbox', { name: 'review_document.delete', exact: true }).setChecked(selected);
         await submit(page);
         const actual = await provider('core/groups/' + editor.pk + '/');
         expect(actual.attributes['qqq.io/permissions'].includes('review_document.delete')).toBe(selected);
         expect(actual.attributes['qqq.io/application-role']).toBe(true);
      }
      for(const inherited of [true, false])
      {
         await action(page, 'authentik_group', 'Review Readers', 'Edit Group');
         await page.getByRole('checkbox', { name: 'Review Editor', exact: true }).setChecked(inherited);
         await submit(page);
         const actual = await provider('core/groups/' + reader.pk + '/?include_parents=true');
         expect((actual.parents_obj || []).map(parent => parent.pk).includes(editor.pk)).toBe(inherited);
         expect(actual.attributes).toEqual(reader.attributes);
         await action(page, 'authentik_user', 'review.sam', 'Edit User Permissions');
         const matrix = page.locator('[data-qqq-id="access-permission-matrix"]');
         await matrix.getByLabel('Show', { exact: true }).selectOption('inherited');
         await matrix.getByLabel('Search permissions or resources', { exact: true }).fill('review_document.edit');
         if(inherited) await expect(matrix).toContainText('Review Editor');
         else await expect(matrix).not.toContainText('Review Editor');
         await page.screenshot({ path: 'target/review-group-inheritance-' + inherited + '.png', fullPage: true });
         await page.getByRole('button', { name: 'Cancel', exact: true }).click();
      }
      const auditResponse = await page.request.post(baseURL + '/qqq/v1/table/authentik_admin_action/query?limit=100', { data: {} });
      const audit = (await auditResponse.json()).records.map(row => row.values).filter(row => row.reason === reason);
      for(const actionName of ['EDIT_PERMISSIONS', 'EDIT_GROUP'])
      {
         expect(audit.filter(row => row.actionName === actionName && row.status === 'SUCCEEDED')).toHaveLength(2);
      }
      console.log('PASS: role permission add/remove, group parent add/remove, inherited user access/source, actual Authentik state and SQL audits. Synthetic groups restored.');
   }
   finally { await browser.close(); }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
