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
| `Arcade/Aclchk/HookBlock.lean` | Layer 1: the shared hook block | `aclchk.c` 3311–3346 (+4 copies) |
| `Arcade/Aclchk/Functions.lean` | Layer 2: the five patched functions; Layer 3: dispatch | `aclchk.c` 3231–4192 |

## Assumptions

* `Env.WellFormed`: native `aclmask()` returns no bits outside `mask`.

## Abstractions

* `aclmask()`, `superuser_arg()`, syscache lookups and the hook are parameters (`Env`).
* `is_missing` treated as non-NULL (missing object → 0 rather than ERROR).
* Built-in roles (`pg_read_all_data` etc.) not yet modelled.
* Memory management and ACL detoasting not modelled.

## Status

| Theorem | File | Status |
|---|---|---|
| `hookBlock_additive` | HookBlock | sorry |
| `hookBlock_sound` | HookBlock | sorry |
| `hookBlock_fail_closed` | HookBlock | sorry |
| `hookBlock_called_iff` | HookBlock | sorry |
| `hookBlock_info` | HookBlock | sorry |
| `pgClass_superuser_no_hook` | Functions | sorry |
| `pgClass_catalog_write_protected` | Functions | sorry |
| `pgAttribute_no_acl_never_asks` | Functions | sorry |
| `pgType_hook_sees_original_oid` | Functions | sorry |
