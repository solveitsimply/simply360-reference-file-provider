# Agent Instructions

## Worktree ownership on Jake’s Macs

- Create every linked worktree under `/Users/jake/GitHub/worktrees/<project>/`, where `<project>` is
  the canonical checkout directory name under `/Users/jake/GitHub`. Use that repository's Git
  metadata and keep one primary clone in `/Users/jake/GitHub`.
- Name the directory `<app>--<agent>--<session-id>--<purpose>`. Use lowercase hyphenated app, agent,
  and purpose labels. The app is the host that owns the session (for example `codex-desktop`,
  `claude-desktop`, or `simply-agent-coder`). The agent is the runtime creating the worktree (for
  example `codex`, `claude-code`, `opencode`, or `cursor`). Use the full, actual owning session ID
  from the host, including for delegated work. Lowercase UUIDs and preserve the case of other IDs.
  Reserve `--` as the field separator. If an ID contains unsafe path characters or `--`,
  percent-encode those bytes and literal percent signs so the ID is recoverable. Use a distinct
  purpose if the session needs more than one checkout.
- Identify the owner before creating a worktree. A task title, date, branch, commit hash,
  abbreviated ID, or generated placeholder cannot serve as the session ID. For example,
  `codex-desktop--codex--01a1bd65-a742-7840-b24e-16cc33090241--worktree-policy` identifies one
  session and checkout.
- If a host's automatic worktree feature cannot honor this path and name, create the linked worktree
  with Git and open it as the session workspace. To relocate an existing worktree, coordinate with
  the owning session, pause processes using it, preserve changes and any lock, use `git worktree
  move`, and update the session's workspace through its host's supported controls. Verify Git
  registration and the session's ability to continue before retiring the old path.

### Worktree size and closeout

- Create a worktree only when the task needs an isolated checkout. Reuse a suitable worktree owned
  by the session. Use sparse checkout when the task's paths are known and the repo supports it.
  Prefer scoped dependencies and checks, documented shared caches, and copy-on-write reuse where the
  repo supports it. Install dependencies and generate artifacts only when a task step requires them.
- At the end of each task, account for every worktree the session or its workers used. As soon as a
  checkout has no remaining work, stop its local processes, verify its changes are integrated or
  recoverable, preserve any needed ignored or untracked files, and remove it with `git worktree
  remove` or the host's supported cleanup action. The parent owns delegated checkout cleanup after
  review. Verify removal in `git worktree list`.
- Retain an active or unrecoverable checkout under its verified owner. Record the path, reason, and
  the event or date when the owner will review it again. Recheck it when that condition is met.
  Treat app-managed workspaces, unmerged work, locks, and unfamiliar artifacts as requiring owner
  review.
