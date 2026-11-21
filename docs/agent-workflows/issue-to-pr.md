# Issue Workflow (Issue → Pull Request → Ready to Merge)

This document defines how an agent handles development work based on a GitHub Issue.
There are two execution modes:

- **Manual mode**: I specify the issue number. Ask questions in this session and wait for my answer.
- **Scheduled mode**: Started by an Orca automation. Pick the target yourself; post questions as Issue comments and end the run.

If the request does not explicitly say "scheduled mode", treat it as manual mode.

## Prerequisites

- Base branch: `main`
- Issue tracker: GitHub Issues
- Reviewers: Copilot and Orca Bot (see "Review Waiting Rules")
- Before using the workflow, create all five labels listed under "Labels" in the target repository.
- **I do the final merge. The agent brings the PR to a mergeable state and reports.**
- Language:
  - Messages in this session (manual mode questions and reports): use the same language as the person who made the request
  - Everything posted to GitHub (Issue comments, PR titles and descriptions, PR comments, review replies, commit messages, branch names): English
  - Issues and comments may be written in Japanese or other languages. Read and understand them as-is, but still write your own GitHub posts in English
  - When referring to Japanese domain terms, UI labels, or error messages, keep the original text (e.g. `「保存」button`) so it can be matched against the issue and the code
  - Do not translate user-facing text in the code (UI strings, messages, etc.) unless the issue asks for it

## Agent Markers

The agent, Orca Bot, and I may all post from the same GitHub account, so account names cannot tell us apart. Use markers instead. Scheduled runs keep no memory between runs, so these markers are also the only record of what has been done.

- Start every GitHub post you write (Issue comments, PR descriptions, PR comments, review replies) with this line:
  `<!-- agent-workflow -->`
- When you set `agent-needs-input` on an issue, start the comment with this line instead:
  `<!-- agent-workflow:needs-input step={step number to resume from} pr={PR number, or none} -->`
- **Feedback** means any review, review comment, or PR comment that does not contain an agent marker, whoever posted it (Copilot, Orca Bot, or me).
- Feedback is **handled** when one of the following is true:
  - Review comment (inline thread): the thread has a reply with an agent marker, or the thread is resolved
  - Review body or top-level PR comment: a later PR comment with an agent marker lists its ID on a line `Handled: {id}, {id}, ...`

---

## Steps

### 1. Understand the issue
- Read the issue body and comments with `gh issue view {number} --comments`, and review the related code
- Share your understanding (goal, acceptance criteria, scope of impact) as a bullet list
  - Manual mode: in this session
  - Scheduled mode: as a comment on the Issue

### 2. Decide on the approach
- Summarize the approach briefly
- If something cannot be decided on your own, or requires a specification decision, present options (pros, cons, recommendation) and do not proceed until you get an answer
  - Manual mode: ask in this session and wait for my answer
  - Scheduled mode: follow "Pausing for input" under "Scheduled Mode Rules"
- If no decision is needed, share the approach and proceed

### 3. Implement
- Name the branch `issue-{number}-{short-description}`
- Keep changes within the scope of the issue (report other problems you notice; do not fix them)
- Add or update tests as needed

### 4. Self-review
Check the following. If anything fails, go back to step 3 (or to steps 1–2 if needed).
- All acceptance criteria of the issue are met
- No issues that could cause bugs (edge cases, error handling, impact on existing features)
- Tests, lint, and type checks pass locally
- The diff contains no unnecessary changes (debug code, unrelated formatting, etc.)

### 5. Create the pull request
- Add the `agent-pr` label to the PR
- Include the following in the PR description:
  - `Closes #{number}`
  - Changes / How to verify / Scope of impact
- After creating it, wait for CI and review results according to "Review Waiting Rules"

### 6. Handle CI and reviews
- If CI fails: identify the cause and fix it
- For each piece of unhandled feedback (see "Agent Markers"), regardless of when it was posted:
  - Do not accept it blindly; judge whether it is valid (reviewers are AI and may be wrong or excessive)
  - Valid: fix it and reply with what you changed
  - Not valid: do not change the code; reply with your reasoning
  - Unsure: do not change the code; consult me
  - Copilot and Orca Bot contradict each other: do not change the code; consult me
  - In every case, mark it as handled as described in "Agent Markers"
- After pushing fixes, wait for re-review according to "Review Waiting Rules"
- If fixing the same cause fails 3 times, stop and report the situation
  - Scheduled mode: follow "Pausing for input" under "Scheduled Mode Rules"

### 7. Final report (do not merge)
When all of the following are true, report without merging and end the work.
- All CI checks pass on the current PR head
- At least one review without an agent marker was submitted on the current head commit (the review's commit ID equals the PR's head SHA)
- All feedback is handled
- No conflicts with the base branch (resolve them if there are any)

Report contents:
- Summary of the changes
- PR URL
- Feedback you did not apply, and why
- Points you were unsure about, and remaining issues

Where to report:
- Manual mode: in this session
- Scheduled mode: as a PR comment (with an agent marker), and change the issue label from `agent-in-progress` to `agent-done`

---

## Review Waiting Rules

There are two reviewers, and they arrive at different times.
- **Copilot**: reviews automatically when the PR is created (usually within a few minutes)
- **Orca Bot**: starts reviewing at minute 0 of every hour
  - It posts from a regular user account, which may be the same account the agent and I use. Tell posts apart with agent markers, not account names

### Waiting in manual mode
1. After creating the PR, wait up to 15 minutes for Copilot's review
2. If Copilot reviews, handle its feedback (step 6)
3. If no review arrives within 15 minutes, or Copilot leaves a comment saying it could not review, assume Copilot hit its usage limit and wait for Orca Bot
   - Wait until 30 minutes past the next top of the hour for Orca Bot's review
   - If it still does not arrive, report to me and end
4. If both reviewers leave reviews, handle both

### Re-review (after pushing)
- Copilot: if no re-review arrives automatically, re-request it
- Orca Bot: wait for the next top-of-the-hour review (no re-request needed)

### Waiting in scheduled mode
- Do not wait. Handle the CI results and feedback available at that moment, then end the run
- The next run picks up where you left off (see "Choosing a target" under "Scheduled Mode Rules")

---

## Prohibited Actions
- Merging
- Deleting or skipping tests, or changing CI configuration, to make CI pass
- Force pushing, or pushing directly to the base branch
- Changes beyond the scope of the issue

## When Handling Multiple Issues in Parallel
- Do not touch any branch or PR other than the one for your assigned issue
- Always prefix questions and reports with `[#{number}]`
- If your changes may conflict with another issue's changes, stop and consult me

---

## Scheduled Mode Rules

### Labels and transitions

| Label | Meaning |
|---|---|
| `agent-ready` | The agent may start or resume work |
| `agent-in-progress` | The agent is working on it |
| `agent-needs-input` | Waiting for my answer or decision |
| `agent-done` | Ready to merge (waiting for my merge) |
| `agent-pr` | PR created by the agent (applied to PRs) |

| When | Who | Issue label change |
|---|---|---|
| Starting or resuming work | Agent | `agent-ready` → `agent-in-progress` |
| Pausing for input (question or early stop) | Agent | `agent-in-progress` → `agent-needs-input` |
| After answering, or to ask the agent to continue | Me | `agent-needs-input` (or `agent-done`) → `agent-ready` |
| Final report | Agent | `agent-in-progress` → `agent-done` |

### Choosing a target (handle only one per run)
Check the following in order and handle the first match.

1. **Resumed issue**: an open issue labeled `agent-ready` that has a comment with an agent marker
   - Read every comment posted after your last agent-marker comment; these are my answers or instructions
   - If your last agent-marker comment is a `needs-input` marker, resume from its `step`, continuing its `pr` if one is recorded
   - Otherwise, if the issue has a linked open `agent-pr`, resume that PR from step 6
   - Otherwise, resume from step 1
2. **PR in progress**: an open PR labeled `agent-pr` whose linked issue is labeled `agent-in-progress`, and that meets any of the following
   - Has unhandled feedback
   - Has failing CI
   - Has conflicts with the base branch
   - Meets the final-report criteria (step 7)
   → Resume from step 6 (or go to step 7 if only the last condition applies)
3. **New issue**: the oldest open issue labeled `agent-ready` that has no comment with an agent marker
   → Start from step 1

If nothing matches, end without doing anything.

Whenever you start working on the chosen issue, change its label from `agent-ready` to `agent-in-progress` first (to prevent duplicate work).

### Pausing for input
Use this both when you need a question or decision answered and when you stop early (for example, 3 failed fixes or a review that never arrives).

- Post an issue comment starting with the `needs-input` marker (see "Agent Markers")
  - For a question: include the options with pros, cons, and a recommendation
  - For an early stop: describe the situation and what you need from me
- Change the label from `agent-in-progress` to `agent-needs-input` and end the run
- After I reply, I change the label to `agent-ready`. The next run resumes through "Resumed issue"

---

If anything is unclear, stop and ask.
