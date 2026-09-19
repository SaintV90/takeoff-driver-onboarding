# TakeOFF driver onboarding

Simple Node.js prototype for testing courier-driver onboarding.

## Run locally

```powershell
npm install
npm run dev
```

Open `http://localhost:3032` (or the port set in `.env`).

## Email OTP with Gmail

The server generates a six-digit OTP, emails it through a dedicated Gmail account, and stores only a SHA-256 hash of the code. It never sends the OTP back to the browser. Enable two-step verification on the sender Gmail account, create a Google App Password, then set `GMAIL_USER` and `GMAIL_APP_PASSWORD` in the host environment using `.env.example` as a guide. Use this free approach for small-volume demos only.

## Persistence

Test users, applications, document metadata, and files (up to 1 MB per file) are saved in `data/takeoff.json`. The demo reviewer view displays each submitted test application’s captured contact, identity, vehicle, and document metadata, and can mark it **Approved** or **Changes requested**. Drivers see that updated status after signing in.

## Deployment

This app needs a Node host with persistent disk (e.g. Render, Railway, or Fly.io). Set the start command to `npm start`. For durable production data, replace the JSON store with a managed database/object storage service.
