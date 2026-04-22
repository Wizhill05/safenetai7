# SafeNet AI

SafeNet AI is a full-stack scam detection platform built with T3 Stack.

## Stack

- Next.js (App Router)
- tRPC
- Prisma + PostgreSQL (Supabase-compatible)
- NextAuth (credentials auth)
- Tailwind CSS
- shadcn/ui

## Features

- Link Scanner (integrates existing Python API)
- Domain Age Checker (IP2WHOIS API)
- Email Scanner (integrates existing Python API)
- Document Scanner (integrates existing Python API)
- Self-reporting system with instant community visibility
- Protected dashboard with community report feed and scan history

## Environment

Copy `.env.example` to `.env` and update values.

Required variables:

- `DATABASE_URL`
- `DIRECT_URL`
- `AUTH_SECRET`
- `BACKEND_API_URL`
- `IP2WHOIS_API_KEY`
- `GEMINI_API_KEY`

## Run

1. Install dependencies:

```bash
npm install
```

2. Generate Prisma client:

```bash
npx prisma generate
```

3. Apply schema to your database:

```bash
npm run db:push
```

4. Start app:

```bash
npm run dev
```

The app runs on `http://localhost:3000`.

## API Integration Notes

Python backend is consumed via `BACKEND_API_URL` and these endpoints:

- `/scan/link/`
- `/scan/email/`
- `/scan/doc/`

No Python backend logic is rebuilt inside this app.
