/* Copyright 2026 Kingsrook, LLC. Licensed under the Apache License, Version 2.0. */
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { chromium, expect } = createRequire(path.join(process.env.USERPROFILE, '.cache', 'qqq-authentik-access-ui', 'package.json'))('@playwright/test');
const baseURL = 'http://127.0.0.1:18300';
const reason = 'Two-person UI acceptance ' + Date.now();

/** Independently read the synthetic role's actual provider permissions. */
async function role()
{
   const root = fs.readFileSync('target/review-server.log', 'utf8').match(/REVIEW AUTHENTIK (http:\/\/127\.0\.0\.1:\d+)/)?.[1];
   if(!root) throw new Error('Review host not ready');
   const source = fs.readFileSync('src/test/java/com/kingsrook/qbits/authentik/contract/AuthentikTestStack.java', 'utf8');
   const token = source.match(/BOOTSTRAP_TOKEN\s*=\s*"([^"]+)"/)[1];
   const response = await fetch(root + '/api/v3/core/groups/?name=Review%20Editor', { headers: { Authorization: 'Bearer ' + token } });
   if(!response.ok) throw new Error('Provider read failed');
   const groups = (await response.json()).results;
   expect(groups).toHaveLength(1);
   return groups[0];
}

/** Read local records without trusting the process success message alone. */
async function records(page, table)
{
   const response = await page.request.post(baseURL + '/qqq/v1/table/' + table + '/query?limit=100', { data: {} });
   expect(response.ok()).toBeTruthy();
   return (await response.json()).records.map(row => row.values);
}

/** Open a record action using its rendered menu. */
async function action(page, url, name, secondOperator = false)
{
   await page.goto(url);
   await page.getByRole('button', { name: 'Record actions menu', exact: true }).waitFor();
   if(secondOperator)
   {
      // Anonymous UI boot creates a fresh session. Select the review-only
      // second identity after boot and before invoking any write process.
      await page.context().addCookies(['sessionId', 'sessionUUID'].map(cookie =>
         ({ name: cookie, value: 'qbit-authentik-review-second', url: baseURL })));
   }
   await page.getByRole('button', { name: 'Record actions menu', exact: true }).click();
   await page.getByRole('menuitem', { name, exact: true }).click();
}

/** Execute the three-step process, keeping review and result visible. */
async function submit(page, hasDetails = true)
{
   if(hasDetails) await page.getByRole('button', { name: 'Next', exact: true }).last().click();
   await page.getByRole('form', { name: 'Review', exact: true }).waitFor();
   await page.getByRole('button', { name: 'Submit', exact: true }).click();
   await page.getByRole('form', { name: 'Result', exact: true }).waitFor();
}

/** Request as one operator, refuse self-approval, apply as the other, restore. */
async function main()
{
   const initial = await role();
   expect(initial.attributes['qqq.io/permissions'].some(value => value.startsWith('authentik.'))).toBe(false);
   const browser = await chromium.launch({ headless: true });
   try
   {
      const first = await browser.newContext();
      const second = await browser.newContext();
      const requester = await first.newPage();
      const approver = await second.newPage();
      for(const page of [requester, approver])
      {
         page.setDefaultTimeout(20000);
         page.setDefaultNavigationTimeout(20000);
      }
      const groupURL = baseURL + '/app/authentik_group/' + initial.pk;
      await action(requester, groupURL, 'Edit Permissions And App Access');
      await requester.getByRole('checkbox', { name: 'authentik.users.read.hasAccess', exact: true }).check();
      await requester.getByRole('textbox', { name: 'Reason', exact: true }).fill(reason);
      await submit(requester);
      await expect(requester.getByRole('form', { name: 'Result', exact: true })).toContainText('sent for approval');
      const requests = (await records(requester, 'authentik_approval_request')).filter(row => row.reason === reason);
      expect(requests).toHaveLength(1);
      expect(requests[0].requester).toBe('review.operator@example.test');
      expect(requests[0].status).toBe('PENDING');
      expect((await role()).attributes).toEqual(initial.attributes);
      const approvalURL = baseURL + '/app/authentik_approval_request/' + requests[0].id;
      await action(requester, approvalURL, 'Approve And Apply');
      await submit(requester, false);
      await expect(requester.getByRole('form', { name: 'Result', exact: true })).toContainText('cannot approve your own request');
      expect((await records(requester, 'authentik_approval_request')).find(row => row.id === requests[0].id).status).toBe('PENDING');
      expect((await role()).attributes).toEqual(initial.attributes);
      await action(approver, approvalURL, 'Approve And Apply', true);
      await submit(approver, false);
      const decided = (await records(approver, 'authentik_approval_request')).find(row => row.id === requests[0].id);
      expect(decided.status).toBe('APPROVED');
      expect(decided.approver).toBe('review.second@example.test');
      expect((await role()).attributes['qqq.io/permissions']).toContain('authentik.users.read.hasAccess');
      await action(requester, groupURL, 'Edit Permissions And App Access');
      await requester.getByRole('checkbox', { name: 'authentik.users.read.hasAccess', exact: true }).uncheck();
      await requester.getByRole('textbox', { name: 'Reason', exact: true }).fill(reason + ' restore');
      await submit(requester);
      expect((await role()).attributes).toEqual(initial.attributes);
      const audit = await records(requester, 'authentik_admin_action');
      expect(audit.some(row => row.reason === reason && row.status === 'SUCCEEDED' && row.approver === 'review.second@example.test')).toBe(true);
      console.log('PASS: UI approval request, provider unchanged while pending, self-approval refused, distinct live second operator approval, provider grant and SQL audit, role restored.');
   }
   finally { await browser.close(); }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
