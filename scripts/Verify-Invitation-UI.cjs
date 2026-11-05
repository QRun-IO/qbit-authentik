/* Copyright 2026 Kingsrook, LLC. Licensed under the Apache License, Version 2.0. */
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { chromium, expect } = createRequire(path.join(process.env.USERPROFILE, '.cache', 'qqq-authentik-access-ui', 'package.json'))('@playwright/test');
let phase = 'startup';

/** Create one synthetic enrollee through UI/email/signup; retain it for review. */
async function main()
{
   const baseURL = 'http://127.0.0.1:18300';
   const log = fs.readFileSync('target/review-server.log', 'utf8');
   const providerURL = log.match(/REVIEW AUTHENTIK (http:\/\/127\.0\.0\.1:\d+)/)?.[1];
   const mailURL = log.match(/REVIEW MAIL (http:\/\/localhost:\d+)/)?.[1];
   if(!providerURL || !mailURL) throw new Error('Review host is not ready');
   const username = 'review.invite.' + Date.now();
   const email = username + '@example.test';
   const reason = 'Rendered invitation acceptance ' + username;
   const browser = await chromium.launch({ headless: true });
   try
   {
      const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
      page.setDefaultTimeout(20000);
      page.setDefaultNavigationTimeout(20000);
      await page.goto(baseURL + '/app/authentik_user');
      await page.getByRole('button', { name: 'Actions', exact: true }).click();
      await page.getByRole('menuitem', { name: 'Invite User', exact: true }).click();
      await page.getByRole('checkbox', { name: 'Review Viewer', exact: true }).check();
      await page.getByRole('textbox', { name: 'Email', exact: true }).fill(email);
      await page.getByRole('textbox', { name: 'Full Name', exact: true }).fill('Review invitation acceptance');
      await page.getByRole('textbox', { name: 'Reason', exact: true }).fill(reason);
      phase = 'review selected role';
      await page.getByRole('button', { name: 'Next', exact: true }).last().click();
      await page.getByRole('form', { name: 'Review', exact: true }).waitFor();
      await expect(page.getByRole('form', { name: 'Review', exact: true })).toContainText('after enrollment: Review Viewer');
      phase = 'submit invitation';
      await page.getByRole('button', { name: 'Submit', exact: true }).click();
      await page.getByRole('form', { name: 'Result', exact: true }).waitFor();
      await expect(page.getByRole('form', { name: 'Result', exact: true })).toContainText('1 invitation was sent');

      let message;
      phase = 'local email delivery';
      await expect.poll(async () =>
      {
         const list = await (await fetch(mailURL + '/api/v1/messages')).json();
         message = list.messages.find(item => item.To.some(recipient => recipient.Address === email));
         return Boolean(message);
      }, { timeout: 60000 }).toBeTruthy();
      const body = await (await fetch(mailURL + '/api/v1/message/' + message.ID)).json();
      const links = [...(body.HTML || '').matchAll(/href=["']([^"']+)["']/g)].map(match => match[1].replaceAll('&amp;', '&'));
      const link = links.find(value => value.includes('itoken='));
      if(!link || new URL(link).origin !== providerURL) throw new Error('Unexpected invitation link');
      const invitationId = new URL(link).searchParams.get('itoken');
      const signup = await browser.newPage();
      phase = 'browser enrollment';
      signup.setDefaultTimeout(20000);
      await signup.goto(link);
      await signup.getByRole('textbox', { name: 'Username', exact: true }).fill(username);
      await signup.getByRole('button', { name: 'Continue', exact: true }).click();
      phase = 'automatic assignment';
      await expect.poll(async () =>
      {
         const response = await page.request.post(baseURL + '/qqq/v1/table/authentik_invitation_assignment/query?limit=100', { data: {} });
         const rows = (await response.json()).records;
         return rows.find(row => row.values.invitationId === invitationId)?.values.status;
      }, { timeout: 60000, intervals: [1000, 2000] }).toBe('COMPLETE');

      const source = fs.readFileSync('src/test/java/com/kingsrook/qbits/authentik/contract/AuthentikTestStack.java', 'utf8');
      phase = 'provider and audit verification';
      const token = source.match(/BOOTSTRAP_TOKEN\s*=\s*"([^"]+)"/)[1];
      const headers = { Authorization: 'Bearer ' + token };
      const users = await (await fetch(providerURL + '/api/v3/core/users/?username=' + username, { headers })).json();
      expect(users.results).toHaveLength(1);
      const roles = await (await fetch(providerURL + '/api/v3/core/groups/?name=Review%20Viewer&include_users=true', { headers })).json();
      expect(roles.results).toHaveLength(1);
      expect(roles.results[0].users).toContain(users.results[0].pk);
      const auditResponse = await page.request.post(baseURL + '/qqq/v1/table/authentik_admin_action/query?limit=100', { data: {} });
      const audits = (await auditResponse.json()).records.map(row => row.values);
      expect(audits.filter(row => row.reason === reason && row.actionName === 'ADD_MEMBER' && row.status === 'SUCCEEDED')).toHaveLength(1);
      console.log('PASS: UI invitation, local email, browser signup, native webhooks, completed SQL intent, actual role membership and one successful membership audit.');
      console.log('Synthetic enrollee retained for review: ' + username);
   }
   finally { await browser.close(); }
}

// Browser errors can contain the one-time invitation URL. Do not log their bodies.
main().catch(error => { console.error('FAIL: invitation UI acceptance at ' + phase + ' (' + error.name + '); inspect synthetic records and sanitized host logs.'); process.exitCode = 1; });
