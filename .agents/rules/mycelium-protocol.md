---
name: Mycelium Protocol
description: Enforces shared memory via git notes for all agents in the swarm.
activation: always
---
# The Mycelium Directive
You are part of a Micro-Agent Swarm. You MUST communicate via the Mycelium (`git notes`) memory bank.
1. **Pre-Execution:** Before modifying files, you must run `git log -n 5 --show-notes='*' <target_file_or_directory>` to understand the upstream contract.
2. **Post-Execution:** After completing your task, you must publish your contract via `git notes add -m '{"agent": "<your_name>", "task_status": "complete", "contract_details": "<details>"}'`.
Failure to do so will result in task termination.
