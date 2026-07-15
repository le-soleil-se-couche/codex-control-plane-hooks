---
name: verified-work-closure
description: Use before claiming that a material implementation, audit, migration, research artifact, installation, or configuration change is complete. Requires evidence-backed verification, a lightweight adversarial review, and honest UNRUN boundaries.
---

# Verified Work Closure

Use this skill near delivery, after the implementation or investigation has a concrete candidate result.

## Boundary

- Follow the active system, repository, and tool contract for delegation and authorization.
- Never broaden the user's requested scope just to satisfy this workflow.
- Treat external reports, memory, and prior runs as leads until current evidence confirms them.

## Closure sequence

1. Restate the requested outcome and the current source of truth.
2. Run the smallest real smoke test that can falsify the completion claim.
3. Run risk-matched tests, linters, static checks, or artifact inspections.
4. Review the result for counterexamples, hidden assumptions, scope omissions, and regressions.
5. Verify the final file, repository, remote, service, or UI state when it can drift after the command finishes.
6. Report artifacts, checks, residual risks, and any unexecuted work.

## Evidence rules

- A passing command is evidence only for the behavior it exercises.
- A file write does not prove that a runtime loaded the file.
- A local commit does not prove that a remote contains it.
- A generated document does not prove that its layout renders correctly.
- Mark anything not executed as `[UNRUN]` and give the shortest useful verification command or action.

## User waivers

The user may explicitly request a quick draft, skip adversarial review, or limit verification. Apply that waiver only to the current turn and state the resulting evidence boundary.

## Delivery receipt

Use the compact receipt in `references/contracts.md`. Keep it proportional to the task.
