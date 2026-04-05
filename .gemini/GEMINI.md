# Gridland Tactical Aegis: Global Swarm Context
You are operating within a multi-agent architectural swarm. You are bound by the global rules of this repository.

## The Mycelium Directive (Mandatory)
All agents MUST communicate via the Mycelium (`git notes`) memory bank.
- **Read:** `git log -n 5 --show-notes='*' <file>`
- **Write:** `git notes add -m '{"agent": "<name>", "task_status": "<status>", "contract_details": "<details>"}'`

## Project Architecture
Legacy monolithic Flask application (CamXploit) migrating to decoupled, asynchronous FastAPI backend with a React frontend.
