---
name: mycelium-sync
description: Teaches the agent how to read and write to the Git Notes memory bank. Use when you need to publish or retrieve contracts.
---
# Mycelium Sync Operations
## When to use this skill
- Use this when waking up to find instructions from an upstream agent.
- Use this before going to sleep to publish your output interfaces.

## Execution Syntax
- **To Read:** `git fetch origin 'refs/notes/*:refs/notes/*'` followed by `git notes show`
- **To Write:** `git notes add -m '<json_payload>'`
- **To Overwrite:** `git notes add -f -m '<json_payload>'`
