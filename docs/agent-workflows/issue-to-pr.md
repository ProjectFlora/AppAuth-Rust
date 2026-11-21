# Issue Workflow (Issue → Pull Request → Ready to Merge)

This document defines how an agent handles development work based on a GitHub Issue.
There are two execution modes:

- **Manual mode**: I specify the issue number. Ask questions in this session and wait for my answer.
- **Scheduled mode**: Started by an Orca automation. Pick the target yourself; post questions as Issue comments and end the run.

If the request does not explicitly say "scheduled mode", treat it as manual mode.

## Prerequisites

- Base branch: `{main}`
- Issue tracker: GitHub Issues
- Reviewers: Copilot and Orca Bot (account: `{orca-bot-account}`)
- **I do the final merge. The agent brings the PR to a mergeable state and reports.**
- Language:
  - Messages in this session (manual mode questions and reports): use the same language as the person who made the request
  - Everything posted to GitHub (Issue comments, PR titles and descriptions, PR comments, review replies, commit messages, branch names): English
  - Issues and comments may be written in Japanese or other languages. Read and understand them as-is, but still write your own GitHub posts in English
  - When referring to Japanese domain terms, UI labels, or error messages, keep the original text (e.g. `「保存」button`) so it can be matched against the issue and the code
  - Do not translate user-facing text in the code (UI strings, messages, etc.) unless the issue asks for it

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
  - Scheduled mode: follow "When a question or decision is needed" under "Scheduled Mode Rules"
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
- If reviewers leave comments:
  - Do not accept comments blindly; judge whether each is valid (reviewers are AI and may be wrong or excessive)
  - Valid: fix it and reply to the thread with what you changed
  - Not valid: do not change the code; reply to the thread with your reasoning
  - Unsure: do not change the code; consult me
  - Copilot and Orca Bot contradict each other: do not change the code; consult me
- After pushing fixes, wait for re-review according to "Review Waiting Rules"
- Do not handle the same review twice
  - Only treat reviews and comments posted after your last push as new
- If fixing the same cause fails 3 times, stop and report the situation

### 7. Final report (do not merge)
When all of the following are true, report without merging and end the work.
- All CI checks pass
- Every review comment has been addressed or replied to
- No conflicts with the base branch (resolve them if there are any)

Report contents:
- Summary of the changes
- PR URL
- Review comments you did not apply, and why
- Points you were unsure about, and remaining issues

Where to report:
- Manual mode: in this session
- Scheduled mode: as a PR comment, and change the Issue label to `agent-done`

---

## Review Waiting Rules

There are two reviewers, and they arrive at different times.
- **Copilot**: reviews automatically when the PR is created (usually within a few minutes)
- **Orca Bot** (`{orca-bot-account}`): starts reviewing at minute 0 of every hour
  - It appears as a human account, but treat it as an AI reviewer

### Waiting in manual mode
1. After creating the PR, wait up to 15 minutes for Copilot's review
2. If Copilot reviews, handle its comments (step 6)
3. If no review arrives within 15 minutes, or Copilot leaves a comment saying it could not review, assume Copilot hit its usage limit and wait for Orca Bot
   - Wait until 30 minutes past the next top of the hour for Orca Bot's review
   - If it still does not arrive, report to me and end
4. If both reviewers leave reviews, handle both

### Re-review (after pushing)
- Copilot: if no re-review arrives automatically, re-request it
- Orca Bot: wait for the next top-of-the-hour review (no re-request needed)

### Waiting in scheduled mode
- Do not wait. Handle the CI results and reviews available at that moment, then end the run
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

### Choosing a target (handle only one per run)
Check the following in order and handle the first match.

1. **PR in progress**: an open PR labeled `agent-pr` that meets any of the following
   - Has unhandled reviews or comments since the last push
   - Has failing CI
   - Has conflicts with the base branch
   - Meets the final-report criteria and its linked issue is not yet labeled `agent-done`
   → Resume from step 6
2. **Answered issue**: an issue labeled `agent-ready` that has a question you previously posted
   → Read the comments for the answer and resume from where you stopped
3. **New issue**: the oldest open issue labeled `agent-ready`
   → Start from step 1

If nothing matches, end without doing anything.

### When starting work
- Remove `agent-ready` from the issue and add `agent-in-progress` (to prevent duplicate work)

### When a question or decision is needed
- Post the question as an Issue comment (with pros, cons, and a recommendation if there are options)
- Change the label to `agent-needs-input` and end the run
- After I answer and re-add `agent-ready`, the next run resumes the work

### When stopping early
- In cases such as 3 failed fixes or a review that never arrives, post the situation as an Issue comment, change the label to `agent-needs-input`, and end the run

### Labels
| Label | Meaning |
|---|---|
| `agent-ready` | The agent may start work |
| `agent-in-progress` | The agent is working on it |
| `agent-needs-input` | Waiting for my answer or decision |
| `agent-done` | Ready to merge (waiting for my merge) |
| `agent-pr` | PR created by the agent (applied to PRs) |

---

If anything is unclear, stop and ask.
