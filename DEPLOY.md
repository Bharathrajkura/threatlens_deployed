# ThreatLens Render Deployment

This folder is a deployment-ready clone of the original app.

## What changed

- The original project was left untouched.
- This copy supports `DATABASE_URL` for Postgres and falls back to local SQLite.
- A `wsgi.py` entrypoint was added for Gunicorn.
- A `/healthz` route was added for Render health checks.
- `render.yaml` provisions a web service and a Postgres database.
- `.gitignore` and `.env.example` were added so secrets and local artifacts stay out of version control.

## Deploy on Render

1. Push this folder to a new GitHub repository.
2. In Render, create a new Blueprint and point it at that repository.
3. Render will read `render.yaml`, create the web service and Postgres database, and prompt you for any `sync: false` secrets.
4. Add real values for:
   - `VIRUSTOTAL_API_KEY` if you want VirusTotal enabled
   - `ABUSEIPDB_API_KEY` if you want AbuseIPDB enabled
5. Wait for the first deploy to finish, then open the generated `.onrender.com` URL.

## Local run for this clone

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
