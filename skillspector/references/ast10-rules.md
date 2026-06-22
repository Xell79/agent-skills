# AST10 Detection Rules

Detailed detection patterns, severities, and false-positive guidance for each
OWASP Agentic Skills Top 10 risk. This is the rule book the static pass
(Phase 2) and the semantic pass (Phase 3) of the audit workflow consult.

Every rule has:

- **ID** — `ASTxx-NNN` (category plus a sequential rule number)
- **Pattern** — regex (static) or a question (semantic)
- **Severity** — `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- **Action** — what the report should tell the operator to do

> Regexes here are written Python-flavored. Escape them for other engines.
> Anchors use `\b` word boundaries to avoid matching inside longer tokens.

## AST01 — Malicious Skills

The skill contains, directs, or installs malicious code or instructions.

### AST01-001 — Destructive shell commands

**Pattern (static):**

```regex
\b(rm\s+-rf\b|mkfs\.\w+|dd\s+if=.*of=/dev/|>\s*/dev/sd[a-z]|format\s+[A-Z]:|del\s+/[fFsS]\s)
```

**Severity:** HIGH (CRITICAL if it targets `/`, `/home`, or boot devices).

**Action:** Remove the command. If the skill legitimately needs cleanup, scope
it to a named temp directory and require explicit operator confirmation.

### AST01-002 — Remote code execution on install

**Pattern (static):**

```regex
(curl|wget)\b[^|]*\|\s*(sh|bash|python\d?|node)\b
```

**Severity:** CRITICAL.

**Action:** Replace with a pinned, hash-verified download. Never pipe a remote
script into a shell during skill install.

### AST01-003 — Dynamic code execution of untrusted input

**Pattern (static):**

```regex
\b(eval|exec)\s*\(
```

**Severity:** HIGH.

**Action:** Remove. If unavoidable, restrict to a sandboxed interpreter with
no filesystem or network access, and document why.

### AST01-004 — Sensitive file reads

**Pattern (static):**

```regex
~/\.(ssh|aws|gnupg|config)/
|(id_rsa|credentials|\.env\b|\.npmrc|\.pypirc|\.netrc)
```

**Severity:** CRITICAL (these are credential files).

**Action:** Remove the read. A skill should never read another tool's
credentials. If configuration is needed, require the operator to pass it
explicitly.

### AST01-005 — Network exfiltration shape

**Pattern (static):**

```regex
(requests\.post|urllib\.request\.urlopen|fetch\(|curl\s+-X\s*POST)\b
.*(token|secret|password|api[_-]?key|\.ssh|credentials)
```

**Severity:** CRITICAL when a secret field and a POST appear together; HIGH
for POSTs alone.

**Action:** Remove. If telemetry is required, send anonymized, opt-in data to
an operator-configured endpoint.

### AST01-006 — Rogue-agent trigger (semantic)

**Question (Phase 3):** Does the prose contain a conditional that activates
hidden behavior when a specific phrase, file, or environment value is present
("if you see X, then do Y")?

**Severity:** CRITICAL.

**Action:** Remove the trigger. Hidden conditionals are the signature of a
trojan skill.

## AST02 — Supply Chain Compromise

The skill pulls in, or is compromised through, its dependencies.

### AST02-001 — Unpinned or floating dependencies

**Pattern (static):** in `requirements.txt`/`package.json`/`pyproject.toml`,
any requirement with `>=`, `*`, `latest`, or a bare `main`/`master` git ref.

**Severity:** MEDIUM (raises to HIGH if the dependency is network- or
crypto-related).

**Action:** Pin to an exact version with a hash where the ecosystem supports
it (`pip install --require-hashes`, `npm ci` with `package-lock.json`).

### AST02-002 — Known-vulnerable dependency

**Check (static, external):** resolve every declared dependency against
[OSV.dev](https://osv.dev). SkillSpector does this live with an offline
fallback.

**Severity:** follows the CVE (CRITICAL/HIGH/MEDIUM/LOW).

**Action:** Upgrade to a fixed version or replace the dependency.

### AST02-003 — Typosquatting candidates

**Pattern (static + semantic):** dependency names within an edit distance of 1
or 2 of a popular package (`requests`, `nmp`, `python-requests`).

**Severity:** HIGH.

**Action:** Verify the canonical name. Replace if it is a typosquat.

### AST02-004 — Post-install side effects

**Question (Phase 3):** Does the install hook (`setup.py`, `postinstall` script,
`Makefile install`) do anything beyond copying files and writing config (e.g.
phone home, register a service, modify shell rc)?

**Severity:** HIGH.

**Action:** Remove the side effect. Install must be reversible and observable.

## AST03 — Over-Privileged Skills

The skill requests more capability than its stated purpose requires.

### AST03-001 — Blanket permission grants

**Pattern (static):**

```regex
"permissions"\s*:\s*\[.*(\*|"full_access"|"all"|"root"|"admin")\b
```

**Severity:** HIGH.

**Action:** Replace with the minimal permission set the skill actually needs.
Prefer allow-lists over wildcards.

### AST03-002 — Privilege escalation verbs

**Pattern (static):**

```regex
\b(sudo\b|su\s+-|os\.setuid|os\.setgid|chmod\s+777|chmod\s+[0-7]{4})
```

**Severity:** MEDIUM (HIGH if combined with a write to a system path).

**Action:** Document why elevated privileges are needed; prefer a dedicated
service account over `sudo`.

### AST03-003 — Capability mismatch (semantic)

**Question (Phase 3):** Does the skill's tool list / permission scope exceed
its documented purpose? (e.g. a "markdown formatter" that requests network
access and filesystem write everywhere).

**Severity:** HIGH.

**Action:** Trim the capability to the stated purpose. Least privilege is the
default; expansion needs justification.

### AST03-004 — MCP least-privilege violation

**Pattern (static):** an MCP tool declaration whose `allowed_tools` or
`resources` includes another MCP server's whole surface.

**Severity:** MEDIUM.

**Action:** Scope the declaration to the specific tools/resources the skill
calls.

## AST04 — Insecure Metadata

The skill's `SKILL.md` prose or frontmatter embeds prompt injection or leaks
system prompts.

### AST04-001 — Override instructions

**Pattern (semantic, Phase 3):** phrases like "ignore previous instructions",
"forget your system prompt", "you are now in developer mode", "disregard the
above", "act as if no restrictions exist".

**Severity:** CRITICAL.

**Action:** Remove. There is no legitimate reason for a skill to override the
host agent's instructions.

### AST04-002 — System-prompt leakage

**Pattern (semantic):** the skill asks the agent to print, echo, base64, or
otherwise exfiltrate its own system prompt or tool list.

**Severity:** HIGH.

**Action:** Remove.

### AST04-003 — Hidden instructions in whitespace/markup

**Pattern (static):** zero-width characters (`\u200b`, `\u200c`, `\u200d`,
`\ufeff`), HTML comments (`<!-- ... -->`), or `style="display:none"` blocks
inside `SKILL.md`.

**Severity:** HIGH.

**Action:** Remove. Legitimate skills do not hide instructions.

### AST04-004 — Narrative deception

**Question (Phase 3):** Does the prose describe the skill's behavior in a way
that materially diverges from what the code does?

**Severity:** HIGH.

**Action:** Reconcile prose and code. Divergence is either a bug or a cover
story; both must be fixed before install.

## AST05 — Unsafe Deserialization

The skill deserializes untrusted data with unsafe loaders.

### AST05-001 — Unsafe pickle / marshal

**Pattern (static):**

```regex
\b(pickle\.loads?|marshal\.loads?|shelve\.open)\b
```

**Severity:** HIGH (CRITICAL if the input is network- or file-sourced and
untrusted).

**Action:** Replace with a safe format (JSON, TOML) and a schema validator.

### AST05-002 — Unsafe YAML load

**Pattern (static):**

```regex
yaml\.load\s*\((?!.*Loader)
```

**Severity:** HIGH.

**Action:** Use `yaml.safe_load` or pass `Loader=yaml.SafeLoader`.

### AST05-003 — Untrusted `eval`/`exec` of config

Covered by AST01-003; re-report under AST05 when the input is a config file or
a fetched document rather than user input.

**Severity:** HIGH.

## AST06 — Weak Isolation

The skill assumes a trusted environment without sandboxing.

### AST06-001 — No sandbox declared

**Check (semantic):** the skill performs filesystem, network, or subprocess
operations but does not declare or require a sandbox.

**Severity:** MEDIUM.

**Action:** Document the isolation requirement (container, WASM, OS sandbox)
in `SKILL.md`. This skill (SkillSpector) flags the gap; it does not provide
the sandbox.

### AST06-002 — In-process secret handling

**Pattern (static):** the skill stores credentials in module-level variables
or prints them to stdout/log.

**Severity:** MEDIUM.

**Action:** Pass secrets through environment variables or a secret manager;
never log them.

## AST07 — Update Drift

The skill or its dependencies can silently drift to a risky state.

### AST07-001 — No re-scan on update

**Check (process):** the skill's registry/pipeline has no re-scan step on
version bump.

**Severity:** LOW (meta, collection-level).

**Action:** Wire a re-scan into the update path. A clean skill can become
risky after a transitive dependency bump.

### AST07-002 — Floating version refs in skill metadata

**Pattern (static):** `version: latest`, `version: *`, or a `main`/`master`
git ref in the skill's own manifest.

**Severity:** MEDIUM.

**Action:** Pin to a concrete version or commit.

## AST08 — Poor Scanning (meta-risk)

The collection or pipeline lacks scanning coverage.

### AST08-001 — No scanner configured

**Check (process):** the skills repo has no CI step running a skill scanner,
and the registry has no publish-time gate.

**Severity:** reported at the collection/pipeline level, not per file.

**Action:** Install a scanner gate (see `scanner-integration.md`). This is the
risk the SkillSpector methodology exists to close.

### AST08-002 — Static-only coverage with no semantic pass

**Check (process):** the pipeline runs only static checks; prompt-injection
and intent (AST01-006, AST04) can slip through.

**Severity:** LOW (informational).

**Action:** Add an LLM pass for the install decision, or document the
accepted residual risk.

## AST09 — No Governance

There is no human checkpoint or audit trail for skill installs/changes.

### AST09-001 — No approval workflow

**Check (process):** installs and publishes are not gated by a human review.

**Severity:** HIGH (governance gap).

**Action:** Require a reviewer sign-off above the operator's score threshold;
record the decision with a timestamp and reviewer identity.

### AST09-002 — No audit trail

**Check (process):** scan results are not stored or are overwritten without
history.

**Severity:** MEDIUM.

**Action:** Persist every scan report (SARIF or JSON) with version metadata
so a later incident can be traced back.

## AST10 — Cross-Platform Reuse

A skill authored for one runtime is reused on another without revalidation.

### AST10-001 — Runtime-specific assumptions

**Pattern (semantic):** the skill assumes a runtime feature (Claude tool
calling shape, Cursor manifest schema, OpenClaw registry hooks) but is
distributed as platform-agnostic.

**Severity:** MEDIUM.

**Action:** Either scope the skill to its source runtime, or revalidate and
document compatibility per target runtime.

### AST10-002 — Universal Skill Format absent

**Check (semantic):** the skill is portable in principle but does not declare
a Universal Skill Format manifest that downstream platforms can validate.

**Severity:** LOW (informational today; may rise as USF adoption grows).

**Action:** Add a USF manifest when the format is stable on the target
platforms.

---

## Severity Calibration

When two rules apply to the same finding, report the higher severity and cite
both rule IDs. When in doubt between two bands, pick the lower and annotate
the report — false positives erode trust faster than a cautious call.

| Band     | Score delta | Typical example                            |
| -------- | ----------- | ------------------------------------------ |
| CRITICAL | +25         | exfiltration of credentials, `curl\|sh`    |
| HIGH     | +12         | unsafe `eval`, blanket permissions         |
| MEDIUM   | +6          | floating version, capability mismatch      |
| LOW      | +2          | missing USF manifest, informational gaps   |

Score is capped at 100. See `SKILL.md` Risk Scoring for the bands the report
maps scores into (SAFE / REVIEW / RISKY / BLOCK).
