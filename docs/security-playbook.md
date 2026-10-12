# Web App & WordPress Security Playbook

Everything covered in this conversation, organized into one reference: incident response, hardening, and a complete beginner-to-intermediate pentesting methodology for safely testing your own sites.

---

## PHASE 1 — If You Suspect You're Currently Compromised (Do This First)

1. **Take a backup/snapshot before touching anything.**
   You need forensic evidence of the compromised state in case you need to prove what happened or re-check later.

2. **Rotate every credential.**
   - Reset all WordPress admin/user passwords, not just the one you think was breached.
   - Rotate database credentials, hosting/cPanel password, FTP/SFTP, and any API keys (Stripe, email service, etc.).
   - Regenerate WordPress security keys/salts in `wp-config.php` (invalidates all existing login sessions/cookies).

3. **Find and remove rogue accounts.**
   ```sql
   SELECT ID, user_login, user_registered FROM wp_users ORDER BY user_registered DESC;
   SELECT * FROM wp_usermeta WHERE meta_key = 'wp_capabilities' AND meta_value LIKE '%administrator%';
   ```
   Delete any admin account you don't recognize — attackers often hide one here instead of needing your real password at all.

4. **Find what was modified and when.**
   ```bash
   find /path/to/wordpress -type f -mtime -30 -name "*.php" | xargs ls -la
   wp core verify-checksums
   ```

5. **Scan for malware/webshells.**
   - Wordfence (free plugin) — diffs your files against known-good WordPress.org copies.
   - Sucuri SiteCheck (free, no install) — scans externally for blacklist/malware status.
   - With shell access: `clamscan -r /path/to/wordpress --infected --log=scan.log`

6. **Check for a backdoor outside the usual folders.**
   Pay special attention to `wp-content/uploads/*.php` — uploads folders shouldn't be able to execute PHP at all. A `.php` file there is almost certainly the backdoor.

7. **Identify the real entry point before declaring it "fixed."**
   A strong, complex admin password being "cracked" is a red flag that it *wasn't* brute-forced — the keyspace is too large for a login form. Check instead for:
   - An outdated/vulnerable plugin or theme (cross-check versions against WPScan's vulnerability database or Patchstack)
   - A leaked/reused password (breached elsewhere)
   - Phishing or malware (keylogger) on the admin's device
   - Direct database access via SQLi, an exposed backup file, or misconfigured phpMyAdmin

---

## PHASE 2 — Harden WordPress

1. **Update everything, then keep it updated.** Outdated plugins/themes are the #1 real entry point — more common than password attacks.
2. **Lock down XML-RPC.** `wp.getUsersBlogs` and `system.multicall` let attackers run thousands of password guesses in one request, bypassing rate limiting:
   ```bash
   curl -X POST https://yoursite.com/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
   ```
   Disable XML-RPC entirely if unused, or at minimum block those two methods.
3. **Enable 2FA on every admin account.** Highest-leverage single fix — neutralizes credential reuse, phishing, and brute-force at once.
4. **Block PHP execution in the uploads directory** at the server level (`.htaccess`/Nginx config), even if a file gets dropped there.
5. **Put Cloudflare (or similar) in front of the site.** Free tier + bot-fight mode stops a large share of scripted traffic before it reaches WordPress.
6. **Add CAPTCHA to checkout and login** (reCAPTCHA v3 / hCaptcha) — stops carding attacks and bot order spam, since most scripts can't solve it.
7. **Fix the WooCommerce/Stripe order-status issue specifically:**
   - Check your Stripe plugin and exact version.
   - Official `woocommerce-gateway-stripe` ≤10.7.0 → update to 10.8.0+ (CVE-2026-2381: unauthenticated order-status manipulation via `wc_stripe_pay_for_order`).
   - ThemeHigh's "Payment Gateway of Stripe for WooCommerce" → ensure the **webhook signing secret is configured**. If blank, anyone can POST a forged `payment_intent.succeeded` event to your public webhook URL and get a "paid" order with zero real payment.
   - In Stripe Dashboard → Developers → Webhooks, confirm signing and review delivery logs for POSTs that don't match Stripe's real outbound IP ranges.
   - Enable "Hold stock for unpaid orders" and auto-cancel pending orders after X minutes.
8. **Rate-limit at the server/WAF level** — block any IP exceeding N checkout/login attempts per minute.

---

## PHASE 3 — Harden Custom Node/Express Apps

1. **Fix IDOR first — the highest-impact, easiest-to-miss bug class.**
   ```javascript
   // Vulnerable
   const order = await Order.findById(req.params.id);

   // Fixed — scope every lookup to the authenticated user
   const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
   if (!order) return res.status(404).send('Not found');
   ```
   Check every ID-bearing endpoint — read, write, AND delete.

2. **Sanitize MongoDB input to stop NoSQL injection.**
   Add `express-mongo-sanitize` as global middleware to strip `$`/`.` from `req.body`/`req.query`. Enforce types explicitly on login fields:
   ```javascript
   if (typeof req.body.username !== 'string' || typeof req.body.password !== 'string') {
     return res.status(400).send('Invalid input');
   }
   ```
   Also test and guard against `$where` injection (can execute raw JS server-side if enabled).

3. **Pin your JWT algorithm and validate claims.**
   ```javascript
   // Bad
   jwt.verify(token, secret);

   // Good
   jwt.verify(token, secret, { algorithms: ['HS256'] });
   ```
   Explicitly set/check `expiresIn`, `issuer`, `audience`. Never trust a decoded-but-unverified payload for authorization. If using RS256, never let a request pick its own key via `jku`/`kid` headers.

4. **Move JWTs out of localStorage** if stored there — it's XSS-exposed by design in React apps. Prefer httpOnly cookies.

5. **Validate file uploads server-side, not just client-side:**
   - Whitelist extensions server-side.
   - Re-encode/re-process images rather than trusting original bytes.
   - Store uploads outside the webroot with randomized filenames.
   - Parameterize queries for any metadata (filename, description, etc.) submitted alongside uploads.

---

## PHASE 4 — How to Pentest Your Own Sites (Full Methodology)

> **Terminology note:** testing systems you own, with your own authorization, is **white-hat / authorized pentesting** — even though the techniques below are the same ones an attacker would use. No need to think in "red hat / grey hat" terms for your own infrastructure; grey hat specifically implies testing *without* permission, which you don't need to touch here.
>
> **Safety rule that applies to everything below:** test on a **local or staging copy**, never live production — some payloads (SSRF/XXE/webshells especially) can have real side effects, and a "pending" fake order or a dropped test file is harmless on a throwaway copy but not on a site with real customers.

### 4.1 Getting started (if you're new to this)
1. **Install a web proxy** — Burp Suite Community Edition (free). It sits between your browser and the site so you can see and modify every request before it's sent. Use Burp's own "Learn" tab for the browser proxy setup.
2. **Clone your site to a safe copy** — Local by Flywheel or XAMPP for WordPress, or just run your Node app locally. This is your shooting range.
3. **Create two test accounts** (User A, User B), each with some fake data (an order, a profile, a message). This pair is what makes IDOR testing possible.
4. **Practice first on a site built to be hacked** — OWASP Juice Shop (Node/React-style) or DVWA (PHP) — intentionally vulnerable apps with built-in challenges and hints, so you learn the mechanics risk-free before testing anything real.

### 4.2 Reconnaissance (map the attack surface)
- Crawl the whole site logged out, then logged in, with Burp's site map — list every endpoint, parameter, and ID you find.
- Check `robots.txt`, sitemap.xml, and JS bundle source for hidden/unlinked endpoints.
- Enumerate subdomains (`subfinder`, `amass`) — staging/dev subdomains are often less secured.
- Fingerprint tech stack/versions (WPScan for WP, `whatweb`, response headers).
- Check for exposed `.env`, `.git`, or backup files (`/backup.zip`, `/db.sql`) by trying common paths directly.

### 4.3 Authentication & session testing
- Try weak/default creds; test account lockout and rate-limiting on login.
- Test password reset for token predictability, token reuse, or user enumeration via different error messages.
- Test session fixation (does the session ID change after login?).
- Confirm logout actually invalidates the token/cookie server-side, not just client storage.
- JWT tampering with `jwt_tool` (alg confusion, RS256→HS256, weak secret brute-forcing with `hashcat -m 16500`).

### 4.4 Authorization testing (where most real bugs live)
- **IDOR (horizontal privilege):** log in as User A, note an ID it creates (order, file, message). Log in as User B, manually request/modify that same ID. If you get User A's data or can change/delete it as User B, that's confirmed. Use Burp's **Autorize extension** to semi-automate this across your whole site map.
- **Vertical privilege escalation:** as a normal user, hit every `/admin/*` endpoint directly — check the API enforces role checks server-side, not just hiding the button in the UI.
- Check indirect references too: file/attachment downloads by filename, export endpoints, nested resources (`/orders/5521/items/3`), GraphQL resolvers, and WebSocket channel subscriptions.
- Note whether IDs are sequential — if so, any confirmed IDOR becomes enumerable across your whole dataset, which is worth flagging even on its own.

### 4.5 Injection testing
- **SQL/NoSQL injection:** test all form fields, URL params, and JSON bodies with payloads from SecLists' Fuzzing/SQLi folder; use `sqlmap` for automated SQL testing and `NoSQLMap` for Mongo-style injection. Remember SQLi on an upload form is usually in the **filename/metadata fields**, not the file content itself — unless the app parses the file (CSV/XML/JSON) and inserts parsed values unsanitized.
- **Command/template injection:** anywhere input reaches `exec()`, `eval()`, or a template engine.
- **XSS:** stored (profile fields, comments), reflected (search/error pages), DOM-based (anywhere `innerHTML`/`dangerouslySetInnerHTML` touches user input).
- **SSRF:** any feature where your server fetches a URL on your behalf (webhooks, image proxy, PDF export, link previews).

### 4.6 File upload testing
- Extension bypass: double extensions (`shell.php.jpg`), null bytes, case tricks (`shell.PHP`).
- Content-type spoofing: change the `Content-Type` header while the file itself is a script.
- Polyglot files: valid as both an image and a script (GIF+PHP) to bypass "is this really an image" checks.
- Path traversal in filenames (`../../etc/passwd`).
- Reference payload sets: **PayloadsAllTheThings** ("Upload Insecure Files" section), **chndlrx/file-upload-payloads**, **barrracud4/image-upload-exploits** (for apps processing images via ImageMagick/GraphicsMagick).
- Scanners that automate this: **fuxploider**, **GoUpload**.
- A few of these repos include live webshells/EICAR files — treat the test environment as compromised-by-design (isolated container/VM).

### 4.7 Business logic testing (scanners can't find these)
- Checkout: can price/quantity be manipulated client-side before submit? Can an order be marked "paid" without actually hitting the payment gateway?
- Coupon/discount codes: reusable past their limit, or stackable?
- Rate limits on fixed-use actions (referral codes, free trials, OTPs) — can they be brute-forced by retrying?
- Webhook endpoints (Stripe, etc.): try POSTing a forged event with no valid signature and see if it's accepted as real.

### 4.8 Infrastructure checks
- `testssl.sh yoursite.com` for TLS/cert misconfigurations.
- Check for verbose error messages/stack traces leaking file paths.
- Confirm upload directories can't execute server-side code.
- `nikto` for general server misconfiguration/outdated-software scanning.

### 4.9 Tool & repo reference list
| Purpose | Tool/Repo |
|---|---|
| Proxy/manual testing | Burp Suite Community, Burp Autorize extension |
| Automated scanning | OWASP ZAP, `nuclei`, `nikto` |
| WordPress-specific | WPScan, Patchstack vulnerability DB |
| SQL injection | `sqlmap` |
| NoSQL injection | `NoSQLMap` |
| JWT attacks | `jwt_tool`, jwt.io debugger, `hashcat` |
| File upload payloads | PayloadsAllTheThings, chndlrx/file-upload-payloads, barrracud4/image-upload-exploits, SecLists |
| File upload automation | fuxploider, GoUpload |
| Dependency scanning | `npm audit`, Snyk |
| Secrets scanning | `trufflehog`, `git-secrets` |
| Malware/webshell detection | Wordfence, Sucuri SiteCheck, ClamAV, Maldet |
| TLS testing | `testssl.sh` |
| Subdomain enumeration | `subfinder`, `amass` |
| Practice targets | OWASP Juice Shop (Node/React), DVWA (PHP) |
| Methodology reference | OWASP WSTG, OWASP Top 10 |

### 4.10 Document every finding
For each confirmed issue, record: steps to reproduce, impact, and the fix applied. Fix issues as you confirm them rather than batching — a short list of *fixed* bugs beats a long list of untested theories.

---

## Quick Reference — Monthly Recurring Checklist

- [ ] Update WordPress core, all plugins, all themes
- [ ] `npm audit` on every active project
- [ ] Review `wp_users` for unrecognized admin accounts
- [ ] Confirm 2FA is still enabled on all admin accounts
- [ ] Spot-check Stripe webhook logs for unfamiliar source IPs
- [ ] Review server access logs for unusual spikes or patterns
- [ ] Confirm backups are current and restorable
- [ ] Re-run the IDOR two-account test on any new endpoints added that month

---

*Source note: Phases 1-3 and sections 4.2-4.9's attack techniques/tools come directly from this conversation. The beginner setup sequence (4.1), the practice-target recommendation (Juice Shop/DVWA), the tool reference table, and the overall phase structure were added as recommendations to make this complete and easy to follow end-to-end.*
