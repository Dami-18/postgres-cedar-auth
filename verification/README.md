# ARCADE formal verification (Lean 4)

Lean models of the ARCADE PostgreSQL patch, and proofs of the security
properties from the paper (§3.2).

## Build

```sh
cd verification
lake build          # checks every file; warnings list remaining `sorry`s
```

Toolchain: Lean 4.35.0 (pinned in `lean-toolchain`). No external dependencies.

## Layout

| File | Models | C source |
|---|---|---|
| `Arcade/Aclchk/Types.lean` | types, ACL bits, `Env` (abstracted calls), assumptions | `authorization_hook.h`, `parsenodes.h`, `acl.h` |
| `Arcade/Aclchk/AuthorizationHook.lean` | full `AuthorizationInfo`, the hook type, the 5 helpers; refinement to `AuthInfo` | `authorization_hook.h`, `aclchk.c` 90–205 |
| `Arcade/Aclchk/HookBlock.lean` | Layer 1: the shared hook block | `aclchk.c` 3311–3346 (+4 copies) |
| `Arcade/Aclchk/Functions.lean` | Layer 2: the five patched functions; Layer 3: dispatch | `aclchk.c` 3231–4192 |
| `Arcade/Plugin/Types.lean` | request context, Cedar requests, HTTP outcomes, config, cache state | `pg_authorization.c` 89–140, 502–517 |
| `Arcade/Plugin/Response.lean` | HTTP response → GRANT/DENY/IGNORE | `pg_authorization.c` 541–581 |
| `Arcade/Plugin/Cache.lean` | `check_auth_cache`, `update_auth_cache`, `reset_auth_cache` | `pg_authorization.c` 1265–1355 |
| `Arcade/Plugin/Hook.lean` | `cedar_authorization_hook`: chaining, guards, ACL_CHECK per-bit loop | `pg_authorization.c` 363–395, 812–1115 |
| `Arcade/Plugin/System.lean` | core + plugin composed (plugin installed as `Env.hook`) | both |
| `Arcade/Plugin/ContextCache.lean` | concrete run: cached decision reused across client IPs | `pg_authorization.c` 109–115 |
| `Arcade/Plugin/Race.lean` | state machine: in-flight request vs. policy change + reset | `pg_authorization.c` 1095–1100, 1265, 1353 |
| `Arcade/Plugin/Sync.lean` | entity sync from `object_access_hook` / `ProcessUtility_hook` | `pg_authorization.c` 602–805, 1121–1260 |
| `Arcade/Plugin/Security.lean` | whole-system property `Secure`; the plugin as written violates it; a fixed plugin satisfies it and still grants | all of the above |

## Assumptions

* `Env.WellFormed`: native `aclmask()` returns no bits outside `mask`.
* Proofs that use `bv_decide` (for example `hookBlock_additive`, `hookBlock_sound`,
  `pgClass_catalog_write_protected`, `grant_option_reported_for_everyone`) also depend on a `_native.bv_decide` axiom:
  the SAT certificate is checked by compiled code, so they trust the Lean
  compiler. Check with `#print axioms <theorem>`.

* `Security.lean`: Cedar's decision is a `Policy` (one answer per request); the
  agent is `Faithful` (prints that answer as the mock agent's JSON, or fails).
  `fixed_secure` assumes `ParserCorrect` for the JSON parser of the fix;
  `parseDecision_correct` shows a parser meeting it exists.

## Abstractions

* `aclmask()`, `superuser_arg()`, syscache lookups and the hook are parameters (`Env`).
* `is_missing` treated as non-NULL (missing object → 0 rather than ERROR).
* Built-in roles (`pg_read_all_data` etc.) not yet modelled.
* Memory management and ACL detoasting not modelled (`FreeAuthorizationInfo` included).
* In `AuthorizationInfo`: strings are `Option String` (NULL = `none`), `Bitmapset *`
  is `List Int`, `parse_tree` is `Option Unit` (NULL-ness only). The union is
  tagged with the member last written.
* The C hook gets a non-const pointer and could modify the struct; the core
  never reads it afterwards, so the hook is modelled as a pure function.
* Plugin: time is a `Nat`; one hook call uses a single `now`. The Cedar agent at
  a moment is an arbitrary function `CedarReq → HttpOutcome`. Namespace
  prefixes, JSON escaping and name resolution are not modelled.
* Plugin: the DML and DDL/UTILITY branches of `cedar_authorization_hook` are not
  modelled (unreachable: the core only sends ACL_CHECK, see `build_eventType`).
* Plugin: the loop's `1 << i` at `i = 31` is undefined behaviour in C; bit 31
  has no Cedar action, so it is skipped either way, and the model uses `1 <<< 31`.
* Race model: one in-flight request, one tick per step, TTL expiry left out.

## Findings

| Finding | Theorem |
|---|---|
| A non-superuser passes `SELECT WITH GRANT OPTION` checks on every table, without Cedar being asked (the loop scans bits 0–31; grant options are bits 32–63) | `grant_option_reported_for_everyone`, `cedarHook_high_bits_granted` |
| A decision cached for one client IP/day is served to another (context not in the cache key) | `ContextCache.second_granted_from_cache` |
| An answer in flight during a policy change is cached as fresh and served after the reset | `Race.stale_grant_served` (fix: `Race.fixed_never_stale`) |
| A Deny whose diagnostics name a policy `Allow` is read as GRANT (`strstr` on the whole body) | `mapHttp_deny_with_allow_policy_id` |
| Synced entities have no attributes or parents | `Sync.upsert_has_no_attributes` |
| Renaming a table re-syncs the *old* name and never syncs the new one (hook runs before the rename is visible) | `Sync.rename_resyncs_old_name` |
| The entity PUT skips `configure_curl_ssl` | `Sync.upsert_skips_tls_config` |
| `ACL_MAINTAIN`/`SET`/`ALTER_SYSTEM` are logged as "NONE" | `privString_maintain_is_none` |
| Columns with no column ACL never reach Cedar | `pgAttribute_no_acl_never_asks` |
| The core only emits ACL_CHECK; the plugin's DML/DDL branches are dead code | `build_eventType` |

## Status

| Theorem | File | Status |
|---|---|---|
| `init_eventType`, `init_roleid`, `init_queryString_null` | AuthorizationHook | proved |
| `build_eventType` (core only emits ACL_CHECK) | AuthorizationHook | proved |
| `build_readDDL`, `build_readDML_invalid`, `build_names_null` | AuthorizationHook | proved |
| `build_toAuthInfo`, `toFull_build` (refinement) | AuthorizationHook | proved |
| `hook_factors` (justifies `Env.hook`) | AuthorizationHook | proved |
| `EventType.name_injective`, `HookResult.name_injective` | AuthorizationHook | proved |
| `EventType.name_ne_unknown`, `HookResult.name_ne_unknown` | AuthorizationHook | proved |
| `privString_none_of_no_bits`, `privString_select_insert`, `privString_maintain_is_none` | AuthorizationHook | proved |
| `hookBlock_additive` | HookBlock | proved |
| `hookBlock_sound` | HookBlock | proved |
| `hookBlock_fail_closed` | HookBlock | proved |
| `hookBlock_called_iff` | HookBlock | proved |
| `hookBlock_info` | HookBlock | proved |
| `pgClass_superuser_no_hook` | Functions | proved |
| `hookBlock_no_new_write_bits` (helper) | Functions | proved |
| `catalog_strip_clears` (helper) | Functions | proved |
| `pgClass_catalog_write_protected` | Functions | proved |
| `pgAttribute_no_acl_never_asks` | Functions | proved |
| `pgType_hook_sees_original_oid` | Functions | proved |
| `mapHttp_grant_iff`, `mapHttp_curlError`, `mapHttp_not_200`, `mapHttp_allow`, `mapHttp_deny`, `mapHttp_deny_with_allow_policy_id` | Plugin/Response | proved |
| `updateCache_size`, `checkCache_disabled`, `reset_invalidates`, `lookup_mem`, `checkCache_sound`, `updateCache_sound` | Plugin/Cache | proved |
| `cedarHook_disabled`, `cedarHook_superuser`, `cedarHook_no_url`, `cedarHook_prev_wins` | Plugin/Hook | proved |
| `bitLoop_grant`, `bitLoop_skip`, `actionForBit_defined` | Plugin/Hook | proved |
| `cedarHook_grant`, `cedarHook_agent_down`, `cedarHook_high_bits_granted`, `grantOptionSelect_low_clear` | Plugin/Hook | proved |
| `cacheSound_of_noServable`, `withCedar_hookBlock`, `grant_option_reported_for_everyone` | Plugin/System | proved |
| `cedar_denies_outside`, `first_asks_and_grants`, `second_granted_from_cache` | Plugin/ContextCache | proved |
| `stale_grant_served`, `fixed_same_trace`, `inv_init`, `mem_insertEntry`, `inv_step`, `inv_run`, `fixed_never_stale` | Plugin/Race | proved |
| `Secure.pgClass`, `original_not_secure`, `bitLoop_allow_all`, `mapHttp_denyAllowReason`, `allow_reason_not_secure` | Plugin/Security | proved |
| `parseDecision_correct`, `parseDecision_denyAllowReason`, `mapHttpFixed_faithful`, `bitLoopFixed_grant`, `fixed_secure`, `fixed_secure_fresh` | Plugin/Security | proved |
| `bitLoopFixed_complete`, `fixed_complete` | Plugin/Security | proved |
| `create_table_upserts`, `drop_table_deletes`, `index_not_synced`, `sync_disabled`, `sync_resets_cache`, `upsert_has_no_attributes`, `rename_resyncs_old_name`, `upsert_skips_tls_config`, `create_role_synced_once` | Plugin/Sync | proved |
