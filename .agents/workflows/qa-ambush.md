# QA Adversary Ambush
## Description
Triggers the local QA agent to pull down a cloud PR and run adversarial Pytest validation.

## Steps
1. Request the PR number from the human operator.
2. Execute: `git fetch origin pull/<PR_NUMBER>/head:test-branch-<PR_NUMBER>`
3. Execute: `git checkout test-branch-<PR_NUMBER>`
4. Read the Mycelium contract for the newly fetched code.
5. Write adversarial Pytest scripts into the `tests/` directory to aggressively break the implementation.
6. Execute the tests and report the results to the chat.
