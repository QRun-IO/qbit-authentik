# Using access tokens

An access token lets a script, a CLI or another service call a QQQ app as you, without a browser sign-in. In apps that sign in with Authentik, access tokens are Authentik **app passwords**, managed from inside the app by `qbit-authentik`. The design is in [DESIGN.md §13](DESIGN.md#13-access-tokens-qqqs-personal-access-tokens-revision-6).

## Create a token

1. Open **Preferences → Access tokens**. It's also in the user menu under **Access tokens**.
2. Choose **Create token** and fill in:
   - a description, for example "nightly export script";
   - an expiry. It's required: at most 90 days for people, and 365 for service accounts;
   - optionally, a **scope**: read only, and/or only some apps and tables. A scoped token can never do more than you can, and loses access as soon as you do.
3. Copy the key from the dialog. **It is shown once.** The app does not keep it, and nobody can show it again. If you lose it, rotate the token.

The dialog also shows ready-to-run examples for this app, with its real URLs.

## Use a token

Tokens are exchanged for a short-lived access token (a JWT) at the Authentik token endpoint. You then call the app with that JWT.

```sh
# 1. Exchange the token for a JWT (valid for the app's access-token lifetime)
JWT=$(curl -s -X POST "https://auth.example.com/application/o/token/" \
  -d grant_type=client_credentials \
  -d client_id="$APP_CLIENT_ID" \
  -d username="$YOUR_USERNAME" \
  -d password="$QQQ_TOKEN" \
  -d scope="openid profile email" | jq -r .access_token)

# 2. Call the app
curl -s -H "Authorization: Bearer $JWT" "https://app.example.com/qqq/v1/metaData"
```

- Keep the token in a secret store or an environment variable. Never commit it.
- When the JWT expires (the API answers 401), repeat step 1.
- Every exchange is recorded as a sign-in in Authentik. The app shows the token's **last used** time from those records.

## Manage your tokens

From **Preferences → Access tokens**:

| Action | What happens |
|---|---|
| **Rotate** | A new key replaces the old one. The description, expiry and scope stay the same. The old key stops working at once. |
| **Extend** | Moves the expiry. The limit counts from today. |
| **Revoke** | Deletes the token in Authentik. Anything using it stops working at once. |

You get a reminder in the notification bell, and by email, 7 days and 1 day before a token expires.

## For administrators

People with `authentik.tokens.manage` see **all** tokens in the Identity app (**Tokens**). From there they can:
- filter by person, intent and expiry, and sort by age and last use;
- revoke tokens one at a time or in bulk, for example the tokens the home page lists as unused for 60 days, or as belonging to deactivated people;
- create a **service account** for an integration (**Users → Create Service Account**). The account gets one app password, shown once, and the groups you choose. Rotate and extend it from its token record.

Administrators can never create, rotate or extend a token for **another person**. Each person manages their own.

Accounts that can administer Authentik, the break-glass account and the app's own service account can't get tokens from the app at all. Use the Authentik admin UI for them if you really need one.

## Security notes

- A token can do what its owner can do, or less if it's scoped. Prefer a scoped token and a short expiry.
- Tokens for people are created as that person, through Authentik. The app's own service account cannot create a token for a person.
- Every create, rotate, extend and revoke is audited in the app (`authentik_admin_action`, with the channel it came from) and in Authentik's event log.
- The key exists only in Authentik and in the one response that showed it to you.
