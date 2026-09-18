# Personal Hub — email dashboard + calendar + journal

Single-user web app. Connect Gmail accounts via Google OAuth (each account once),
see a combined inbox, a merged calendar, and keep a private journal that can link
emails. Optional AI helpers (summarize email, daily journal prompt) via OpenAI.

## Deploy (Render)

1. Render dashboard → **New → Blueprint** → connect this repo. It creates the web
   service + a Postgres database.
2. After deploy, open **Environment** on the web service and add:
   - `APP_PASSWORD` — the password you type to open the hub (pick anything strong)
   - `FERNET_KEY` — generate one: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` — from the Google Cloud steps below
   - `OPENAI_API_KEY` — optional; enables the ✨ AI buttons
3. Save — the service restarts automatically.

## Google Cloud setup (one time, ~20 min)

1. Go to <https://console.cloud.google.com/> → create a project (any name).
2. **APIs & Services → Library**: enable **Gmail API** and **Google Calendar API**.
3. **APIs & Services → OAuth consent screen**:
   - User type: **External** → Create.
   - Fill app name + your email. Add every Gmail address you'll connect under
     **Test users**. Save.
   - **IMPORTANT:** click **PUBLISH APP** (moves it to "In production"). You do
     *not* need Google verification for personal use — publishing just stops
     Google expiring your login every 7 days. You'll see a one-time
     "Google hasn't verified this app" warning per account → Advanced → Continue.
4. **APIs & Services → Credentials → Create Credentials → OAuth client ID**:
   - Application type: **Web application**.
   - **Authorized redirect URI**: `https://<your-service>.onrender.com/oauth/callback`
     (use your real Render URL from step 1).
   - Create → copy the **Client ID** and **Client secret** into Render env vars.

## Connect accounts

Open the hub → sign in with your `APP_PASSWORD` → **Accounts** tab →
**+ Connect a Gmail account** → sign in with that Gmail → Allow. Repeat per account.

## Outlook / Hotmail (no Azure needed)

In each Hotmail account: outlook.com → ⚙ Settings → **Mail → Forwarding** →
enable, enter your Gmail address, save. Mail flows into Gmail and appears in the
hub. To reply *as* the Hotmail address: Gmail → Settings → Accounts →
"Send mail as" → add the address.
