# CyberSentinelAI — Phase 1 Extended

This extended scaffold includes:

- Backend with /run-simulation background runner and /alerts/latest retrieval
- React (Vite) dashboard to trigger simulation and view alerts
- Integration test (pytest) that can run an end-to-end smoke test (requires Docker)

Quick start:

1. Ensure Docker and Docker Compose are installed.
2. From this directory run:
   docker compose up -d --build
3. Visit the dashboard at http://localhost:3000
4. Use the dashboard's Run Simulation button (will POST to backend and insert simulated logs into MongoDB).

Notes:
- Attack scripts are intentionally simulated and require sandbox mode.
- The integration test is skipped by default; remove the skip marker to run in CI with Docker.
