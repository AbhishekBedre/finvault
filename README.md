# FinVault

**A private, encrypted vault for your cards, net-banking details, logins and important dates — that lives only on your own device.**

No account. No server. No sync. No tracking. Your data never leaves the browser it was typed into.

### 👉 Open the app: **https://AbhishekBedre.github.io/finvault/**

Works on Android, iPhone/iPad, Windows, macOS, Linux and ChromeOS — anywhere there is a modern browser.

---

## Install it (takes 20 seconds)

FinVault is a Progressive Web App (PWA). Open the link above, then install it so it runs full-screen like a normal app and works offline.

### 🤖 Android (Chrome, Edge, Samsung Internet)
1. Open **https://AbhishekBedre.github.io/finvault/** in Chrome.
2. Tap the **⬇ Install app** button on the sign-in screen (or open the **⋮ menu → Install app / Add to Home screen**).
3. Confirm. FinVault appears in your app drawer and home screen.

> On Android the installed app and Chrome **share the same storage** — clearing Chrome's site data also clears the installed app's vault.

### 🍎 iPhone / iPad (Safari)
1. Open **https://AbhishekBedre.github.io/finvault/** in **Safari** (iOS 16.4 or later recommended).
2. Tap the **Share** button (square with an up arrow).
3. Scroll down and tap **Add to Home Screen** → **Add**.
   *(If you don't see it, scroll to the bottom of the share sheet and tap **Edit Actions** to turn it on.)*

> iOS never shows an "Install" button or pop-up — **Add to Home Screen is the only way**, and it's normal.
> The Home Screen app has **its own separate storage** from Safari. If you already created a vault in Safari, export a backup there and restore it in the installed app (see [Moving data between devices](#moving-data-between-devices)).

### 💻 Windows / macOS / Linux / ChromeOS
- **Chrome or Edge:** click the **install icon** (⊕ / monitor with arrow) at the right end of the address bar, or **⋮ menu → Install FinVault**.
- **Safari on macOS (Sonoma or later):** **File → Add to Dock**.
- **Firefox:** desktop Firefox can't install web apps — just use the page in a tab or bookmark it. Everything else works the same.

You can also skip installing and simply use it in a browser tab. Installing just gives you a cleaner, app-like experience and better protection from the browser automatically deleting your data.

---

## ⚠️ Read this first: where your data lives

FinVault has **no backend**. Everything you enter is stored **inside your browser, on the device you are using** (in the browser's IndexedDB storage for this site).

That has important consequences:

| Situation | What happens to your vault |
|---|---|
| You use FinVault on your phone **and** your laptop | They are **two completely separate vaults**. Nothing syncs between them. |
| You sign in to Chrome / Safari / iCloud / Google with the same account on both | **Still no sync.** Browser sync covers bookmarks, passwords, history and tabs — **not** a website's stored data. |
| You add an entry on your phone | It is **not** visible on your laptop (and vice versa). |
| You uninstall FinVault from the Home Screen (iOS) | The app's data is **deleted**. |
| You get a new phone | The vault does **not** come with you, unless you export a backup and import it on the new phone. |

> **The only way to move or protect your data is the encrypted backup file** (Profile → Export backup). Make backups regularly.

---

## 🗑️ How your data can be deleted (accidentally)

Because the vault is stored as browser "site data", clearing the browser's site data **deletes the vault permanently**. There is no cloud copy and no way for anyone — including the developer — to recover it. Even if you remember the master password, **the data is gone**.

**Your vault will be deleted if you:**

- **Chrome (Android / desktop):** *Clear browsing data* with **"Cookies and site data"** ticked (any time range that includes your vault). Clearing only "Cached images and files" or "Browsing history" is safe.
- **Android Settings → Apps → Chrome → Storage → Clear data / Clear storage**, or **Uninstall Chrome**.
- **Safari (iPhone / iPad):** *Settings → Safari → Clear History and Website Data*, or *Advanced → Website Data → remove FinVault's site*.
- **Safari (Mac):** *Safari → Settings → Privacy → Manage Website Data → Remove*, or clear history for "all history".
- **Remove the Home Screen app on iPhone** (long-press the icon → Remove App).
- Use **private / incognito windows** — storage there is thrown away when the window closes.
- Run "cleaner" apps, privacy tools or browser extensions that wipe site data on exit.
- Reset or erase the device, or delete the browser profile.

**The browser may also delete data on its own:**

- When the device is **very low on storage**, browsers can evict site data that isn't marked "persistent". FinVault asks the browser for persistent storage when you sign in (Profile → Backup & data shows whether it was granted) — Chrome and Safari grant it mainly to **installed** apps you use regularly.
- **Safari (iOS) in a normal tab** may remove a website's data if you haven't used that site for about **7 days**. Apps **added to the Home Screen** are exempt from this — another good reason to install FinVault.

**How to protect yourself:**

1. **Install the app** (Add to Home Screen / Install).
2. **Export a backup** regularly: Profile → **Export backup**. On phones this opens the share sheet — choose **Save to Files → iCloud Drive** (iPhone) or **Drive / Files** (Android).
3. FinVault shows a **banner** if you have entries and haven't backed up in 7 days, and Profile shows the date of your last backup.
4. Before clearing browser data, **export a backup first**.

---

## 🔐 Security: how your data is protected

### Encryption
- Everything you save (entries, card and bank details, logins, reminders, profile, settings) is **encrypted before it is written to storage**.
- **Algorithm:** AES-256-GCM (authenticated encryption) using the browser's built-in **Web Crypto API** — no third-party crypto library.
- **Key derivation:** your **master password** is stretched with **PBKDF2-SHA-256, 310,000 iterations** and a **random 16-byte salt**, producing the 256-bit key. A fresh random 12-byte IV is used on every save.
- **Your master password is never stored** and never leaves the device. The key exists only in memory while the vault is unlocked and is discarded when you lock/log out.
- Tampered or corrupted data fails authentication and won't open.
- Minimum master password length is 10 characters. **Use a long, unique password** — it is the only thing protecting your vault.

### ❗ No password recovery
There is **no "forgot password"**. The master password is the encryption key. If you forget it, the vault **cannot be recovered by anyone** — not even from a backup file (backups are encrypted with the same password). Keep the password somewhere safe.

### No network, no tracking
- The app makes **no requests to any server with your data**. There is no database, no API, no analytics, no ads, no cookies, no third-party scripts, fonts or CDNs.
- The only network use is downloading the app's own files (HTML, icons) from GitHub Pages. A service worker caches **only those app files** so the app opens offline — **never your data**.
- Reminder notifications (if you enable them) are generated locally on your device and show only the reminder title.

### Day-to-day protections
- **Sensitive fields hidden by default:** card number, CVV, PIN and all passwords are masked on screen. They are shown only when you tap **Show** in the details view; cards on the home screen show only the last 4 digits.
- **Auto-lock after inactivity:** 1, 5 (default) or 15 minutes, or never.
- **Lock when you switch away from the app:** immediately, after 30 seconds, after 1 minute (default), or never.
- **Clipboard auto-clear:** copied card numbers, CVVs, PINs and passwords are cleared from the clipboard after 15 / 30 (default) / 60 seconds. *Note: iPhone Safari only lets a web page write to the clipboard right after a tap, so on iPhone this clean-up may silently not happen.*
- **Logout** (bottom of the Profile page) locks the vault and wipes all decrypted data from memory.
- **Change master password** re-encrypts the vault with a new salt and key.
- **Destructive actions need confirmation** ("Delete permanently?").
- Passwords/PINs fields are excluded from search.

### What is *not* encrypted (know this)
| Item | Stored where | Encrypted? |
|---|---|---|
| Entries, reminders, profile, settings | IndexedDB (`vaults`) | ✅ Yes |
| **Attached images** (card photos, documents) | IndexedDB (`images`) as base64 | ❌ **No** — stored as plain image data |
| Theme choice (light / black / auto) | localStorage | ❌ No (harmless preference) |
| App files (HTML, icons) | Service-worker cache | ❌ No (just the public app code) |
| **Backup file** (`.json`) | Wherever you save it | Vault part ✅ encrypted; **images inside it ❌ not encrypted** |

> **Don't attach images of sensitive documents unless you're comfortable with that.** A photo of a card front/back or a cheque attached to an entry is saved unencrypted on the device and in backup files. Anyone who gets that backup file can see the images (but not your text data).

### What FinVault cannot protect against
Being honest about the limits:
- **A compromised device** — malware, spyware, keyloggers, screen recorders, or a malicious browser extension can see what you type and what's on screen while the vault is unlocked.
- **Someone who knows or guesses your master password** and has your device (or a copy of your backup file — a weak password can be brute-forced offline).
- **Someone looking over your shoulder** while the vault is unlocked.
- **A phone left unlocked** — FinVault's own lock helps, but also use your device passcode / biometrics.
- This is a personal, open-source project and **has not been independently security-audited.**

### A word of caution on what you store
Think twice before storing **full card numbers together with CVV and PIN**. Anyone who obtains them together can spend your money. Consider storing only what you really need to look up. Never store OTPs.

---

## Moving data between devices

There is no sync, but you can copy your vault by hand:

1. On the device that has your data: **Profile → Export backup**. Save the file somewhere you can reach (iCloud Drive, Google Drive, AirDrop, email to yourself).
2. On the other device, open FinVault and choose **Restore from a backup file** on the sign-in screen (or **Profile → Import backup**).
3. Sign in with the **same master password** you used when the backup was made.

Importing **replaces** the vault on that device — it is a copy, not a merge. If you add entries on both devices independently, importing one over the other discards the other's new entries. Pick one device as your "main" one.

---

## Features

- **Categories:** Credit cards, Debit cards, Netbanking, Login details, FD details, BOND details, Notes — each with its own fixed colour.
- **Credit / debit cards:** card type (Visa, Mastercard, RuPay, Amex), holder name, co-issuer, bank, number, expiry, CVV, PIN, limit, payment date, description — shown as a card with network badge.
- **Netbanking:** account holder, bank, account number, customer ID, registered mobile, user ID, login / profile / transaction passwords, mobile username / password / login PIN.
- **Login details:** name, username, password.
- **Images:** attach photos to any entry; tap to view full-screen, swipe, and zoom.
- **Reminders (dates only):** payment dates (monthly) and FD / bond maturity dates are added automatically; add your own one-time, monthly or yearly reminders with "remind me N days before".
- **Add to calendar (.ics):** export a reminder (or all of them) to your phone's calendar for alerts even when the app is closed. Download again after editing and your calendar updates the same event.
- **Search**, sort, category filters, copy-to-clipboard, show/hide sensitive values.
- **Profile page** with basic user details, **Light / Black / Auto theme**, security settings and backup tools.
- **Installable & offline:** works without internet after the first load.

### About reminders and notifications
A web app that isn't running can't wake itself up, so in-app alerts fire **only while FinVault is open**. For reliable alerts when the app is closed, use **📅 Add to calendar** — your phone's calendar then notifies you on its own.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| **"Could not open the vault"** / "FinVault is open in another tab or the installed app" | An older copy of the app is still open and blocking an update. **Close all FinVault tabs and the installed app completely**, then open it again. Your data is kept. |
| **No Install button on iPhone** | Normal — iOS never shows one. Use **Share → Add to Home Screen** in **Safari**. |
| **Vault is empty on my other device / after install** | Each browser and each installed app has separate storage. Restore from a backup file. |
| **"Incorrect password, or the vault data is damaged"** | Check the password (case-sensitive). If you restored a backup, use the password from when the backup was made. |
| **Vault disappeared** | Site data was cleared (see [above](#️-how-your-data-can-be-deleted-accidentally)). Restore your latest backup. |
| **App shows an old version** | Close and reopen the installed app once; it updates itself on the next launch. |
| **Reminder alerts don't appear when the app is closed** | Expected — use **Add to calendar**. |

---

## Hosting your own copy (optional)

FinVault is a handful of static files — no build step.

```
index.html
manifest.webmanifest
sw.js
icon-192.png
icon-512.png
icon-maskable-512.png
apple-touch-icon.png
```

1. Put all the files in the root of a GitHub repository (e.g. `finvault`).
2. **Settings → Pages → Deploy from a branch → `main` / root.**
3. Your app is live at `https://<your-username>.github.io/<repo>/`.

It must be served over **HTTPS** (GitHub Pages does this) or from `localhost` — the browser's encryption and install features don't work on plain HTTP. To run locally: `python3 -m http.server 8000`, then open `http://localhost:8000`.

> Important: a vault is tied to the **exact address (origin)** it was created on. `https://AbhishekBedre.github.io` and `http://localhost:8000` — or a different username/domain — are **different storage areas** and cannot see each other's data. If you move to a new address, export a backup first and import it there.

---

## Privacy

FinVault collects **nothing**. There is no server to collect anything. No analytics, no telemetry, no accounts. The developer cannot see, access or recover your data.

## Disclaimer

Provided **as is**, without warranty of any kind. It is a personal convenience tool, **not** a substitute for a professionally audited password manager or bank-grade security. You are responsible for choosing a strong master password, keeping backups, and deciding what information to store. The author is not liable for any loss of data or any other damages arising from its use.
