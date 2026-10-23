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

## Assumptions

* `Env.WellFormed`: native `aclmask()` returns no bits outside `mask`.
* Proofs that use `bv_decide` (`hookBlock_additive`, `hookBlock_sound`,
  `pgClass_catalog_write_protected`, `privString_none_of_no_bits`) also depend on a `_native.bv_decide` axiom:
  the SAT certificate is checked by compiled code, so they trust the Lean
  compiler. Check with `#print axioms <theorem>`.

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
