# Session vs. IP Authentication State

AegisFTP tracks attacker state at two different layers that look similar
but serve different purposes and have different lifetimes. This exists
because of work on Issues #1, #3, #6, and #7, and it's easy to confuse
the two if you're reading `adaptive.py` cold, so this doc exists to make
the split explicit.

## The two layers

### 1. Per-session state (`_adapter_sessions`, `session_states`,
`session_qlearn`, `session_cmd_timestamps`, `session_scan_thresholds`)

Keyed by `session_id`, created fresh on every new FTP connection and
discarded on `QUIT` (see `AdaptiveDeceptionEngine.cleanup_session` and the
`_adapter_sessions.pop(session_id, None)` call in `decide_response`'s
`QUIT` handler).

This layer answers: *"What has this specific connection done so far?"*
- Has this session authenticated?
- How many commands has it sent, and how fast?
- Which directories has it listed (containment gate, Issue #6)?
- What is this session's current deception state/action, and what
  Q-learning reward is pending for the action just taken (Issue #4)?
- What randomized scan threshold (Issue #5) applies to this session?

All of it is intentionally throwaway: when the attacker reconnects, they
get a brand-new session and a blank slate here. That's realistic FTP
server behavior -- a real server doesn't remember your command history
across a disconnect either.

### 2. Per-IP state (`_ip_auth_state`, `_ip_escalation`)

Keyed by the client's source IP address, created on first contact from
that IP and **never cleared by `cleanup_session`**. It survives
reconnects, which is the entire point.

This layer answers: *"What has this attacker, specifically, done across
every connection they've made?"*

- `_ip_auth_state` (Issue #1 / #3): the randomized failed-attempt
  threshold assigned to this IP, and whether it has already been granted
  access. Without this, an attacker who got the honeypot to "grant"
  access after N failed attempts could just disconnect and reconnect to
  reset the counter and brute-force again for free. Per-IP state closes
  that loophole: once granted, `get_ip_auth_state` fast-paths the grant
  on any future connection from that IP instead of making them fail N
  times again.

- `_ip_escalation` (Issue #7): an accumulating "attack score" for the
  IP, built from suspicious signals observed across any of its sessions
  (sensitive-file probing, payload uploads, destructive commands,
  high-frequency scanning). Once the score crosses
  `TRIPWIRE_ESCALATION_THRESHOLD`, the IP is flagged `escalated` and the
  adaptive engine refuses to hand it `NORMAL_RESPONSE` on *any* future
  session, no matter how that session's own state looks in isolation.
  This is deliberately sticky: a sophisticated attacker who notices
  they're being tarpitted and reconnects to "reset" shouldn't actually
  get a reset.

## Why not just use IP for everything?

Because some state is genuinely per-connection and collapsing it into
per-IP state would produce wrong behavior: command rate, directory
listing history, and the pending Q-learning reward are all properties of
*this specific TCP session's conversation*, not of the IP in the
abstract (NAT, shared proxies, and simple reconnects all mean "same IP"
does not mean "same conversation"). Mixing the two would mean one dropped
connection could corrupt the deception state of a completely unrelated
future session from a shared-IP user.

## How they connect

`decide_response(session_id, action, parameters, context)` extracts
`client_ip = context.get("client_ip")` once per call and threads it
through to both layers:

- `get_adapter_session(session_id, client_ip)` seeds a brand-new
  per-session record FROM the per-IP auth state (so a returning attacker
  starts their new session already past the auth gate if they'd already
  earned it).
- `adaptive_engine.evaluate_response(..., client_ip=client_ip)` reads
  and writes the per-IP tripwire score as a side effect of evaluating
  the current command's per-session state.

So a single FTP command touches both layers in the same call: it reads
and mutates this session's throwaway state, while also reading and
potentially mutating this IP's persistent state.

## Known limitation: no cleanup for per-IP state

`cleanup_session()` only clears the five per-session dicts above. Nothing
currently expires entries in `_ip_auth_state` or `_ip_escalation` --
they live for the lifetime of the Python process, for every distinct IP
that has ever connected. On a long-running honeypot exposed to the
internet, this is a slow, unbounded memory leak (same category of issue
as the per-session dicts had before Issue #4's cleanup fix, just on a
different key and a much longer timescale since an IP might come back).

This is intentional for now -- the two issues that created this state
(#1/#3 and #7) specifically need it to survive indefinitely to do their
job -- but a production deployment should add a TTL/LRU eviction policy
(e.g., drop an IP's entry after N days of inactivity) rather than
reaching for per-session-style cleanup, which would defeat the purpose.
