# Secrets Docker

This project is a simple Node.js + Express app built to **test and learn authentication flows** and **Dockerized setup**.

## Main Purpose

This is an experimental/learning project, not a production-ready system.  
It was mainly created to practice:

- Local authentication (email/password)
- Google OAuth authentication
- Session handling with PostgreSQL-backed session storage
- Running the full app stack with Docker and Docker Compose

## Stack

- Node.js + Express
- EJS templates
- PostgreSQL
- Passport (local + Google OAuth)
- Docker & Docker Compose

## Run with Docker

1. Copy `.env.example` to `.env` and fill required values.
2. Build and start:

```bash
docker compose up --build
```

3. Open `http://localhost:<PUBLIC_PORT>` (defaults to `3000`).

## Notes

- The goal of this project is to validate authentication behavior and containerized development workflow.
- It is intentionally minimal and focused on testing auth + Docker integration.
