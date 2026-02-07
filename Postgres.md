PostgreSQL **is designed to be highly extensible**, but not *every subsystem* was originally built with pluggability in mind.
Authentication has hooks (like `ClientAuthentication_hook`) because those parts were intentionally designed to allow external control.
**Authorization (permissions: GRANT/REVOKE)** does *not* have hooks. The permission system is deeply tied to the internal catalog structure, parser, and executor.

So your question is:

> “How can I modify PostgreSQL core to add hooks for authorization decisions (GRANT/REVOKE) similar to authentication hooks?”

Here is the *complete, practical*, low-level roadmap for how PostgreSQL is architected and how you would introduce such a hook cleanly.

---

# ✅ 1. How PostgreSQL Implements Permissions (Today)

PostgreSQL permission checks fundamentally happen in two layers:

### **1. Catalog-level metadata**

Permissions are stored in catalog columns named `relacl`, `proacl`, `datacl`, etc.
These are parsed into a list of `AclItem` structs.

### **2. Code-level checks**

The main checker is:

```
bool pg_class_aclcheck(Oid table_oid, Oid roleid, AclMode mode);
```

There are equivalents for functions, schemas, databases, etc.

All permission checks eventually flow through:

```
aclcheck_error()
```

and:

```
pg_aclmask() / pg_aclmask_ext()
```

These functions are buried inside `src/backend/utils/acl/aclchk.c`.

There are **no callback/hook points** here.

---

# ✅ 2. Why PostgreSQL Has Hooks for AuthN but Not AuthZ

Authentication is performed *once*, before the session starts.

Authorization is performed:

* at parse-time (for some rules)
* at rewrite-time
* during planning
* during execution
* sometimes inside utility commands (DDL)

A hookable system was *not initially designed*, so adding hooks now requires structural work.

---

# ✅ 3. Where You Should Insert a New Authorization Hook

To create a general authorization hook, you want a single choke point that all permission checks converge to.

The **best location** is:

### `pg_aclmask_ext()`

This is the deepest function that all GRANT/REVOKE-based permission checks ultimately end up calling.

Signature:

```c
AclMode
pg_aclmask_ext(const Acl *acl,
               Oid roleid,
               AclMode mask,
               DropBehavior behavior,
               Oid objectId,
               AclObjectKind objkind)
```

Every object access reduces to:

* An object identifier (OID)
* A role ID
* A mode (SELECT, INSERT, EXECUTE, etc)

This is a *perfect spot* for an authorization hook.

---

# ✅ 4. How PostgreSQL Extension Hooks Work Internally

Hooks are implemented using function pointers declared as extern variables, e.g.:

```c
ClientAuthentication_hook_type ClientAuthentication_hook = NULL;
```

Extensions assign to this pointer during `_PG_init()`:

```c
ClientAuthentication_hook = my_auth_hook;
```

Postgres calls the hook at runtime:

```c
if (ClientAuthentication_hook)
    (*ClientAuthentication_hook)(port, status);
```

You can implement an authorization hook *exactly the same way*.

---

# ✅ 5. Implementing a New Authorization Hook (Step-by-Step)

---

## **Step 1 — Add a hook declaration**

In `src/include/utils/acl.h`:

```c
typedef void (*authorization_hook_type)(
    Oid roleid,
    Oid objectId,
    AclObjectKind objkind,
    AclMode requested_mode,
    bool *allow
);

extern PGDLLIMPORT authorization_hook_type authorization_hook;
```

---

## **Step 2 — Add the hook variable**

In `src/backend/utils/acl/aclchk.c`:

```c
authorization_hook_type authorization_hook = NULL;
```

---

## **Step 3 — Call the hook in pg_aclmask_ext**

Edit `pg_aclmask_ext`:

```c
if (authorization_hook)
{
    bool allow = true;
    (*authorization_hook)(roleid, objectId, objkind, mask, &allow);

    if (!allow)
        return 0;  // deny all permissions
}
```

Or if you want the hook to *additionally* deny after core logic:
Call it after native masking.

---

## **Step 4 — Recompile PostgreSQL**

```
./configure --prefix=/usr/local/pgsql
make -j
make install
```

Restart Postgres.

---

## **Step 5 — Build an extension that uses the new hook**

Your extension’s `_PG_init()`:

```c
void
_PG_init(void)
{
    authorization_hook = my_custom_hook;
}

void
my_custom_hook(Oid roleid, Oid obj, AclObjectKind kind,
               AclMode mode, bool *allow)
{
    // Example: disallow everyone from dropping tables
    if (mode & ACL_DROP)
        *allow = false;
}
```

---

# ✅ 6. Additional Integrations You Might Want

### **1. Add hooks for GRANT/REVOKE command parsing**

Modify:

* `src/backend/commands/user.c`
* `src/backend/commands/tablecmds.c`

Add:

```c
grant_revoke_hook_type grant_revoke_hook;
```

User hook could observe changes like:

```c
grant_revoke_hook(roleid, objectid, mode, is_grant);
```

---

### **2. Add hooks into utility command executor**

In `ProcessUtilitySlow`:

```c
if (UtilityAuthorization_hook)
    UtilityAuthorization_hook(pstmt, queryString, context);
```

This gives permission control on:

* CREATE TABLE
* ALTER TABLE
* DROP DATABASE
* TRUNCATE
* VACUUM, etc.

---

# ✅ 7. How Hard Is This to Get Merged Upstream?

Realistic answer:

### ➤ It is extremely unlikely to be accepted upstream.

Why?

* Authorization logic in PostgreSQL is a *security-critical subsystem*.
* Hook-based extensions at this depth increase the risk of privilege escalation.
* Upstream requires a massive RFC, discussion, and a demonstrated community need.

So:

✔ Possible in your own fork
✔ Not accepted upstream (almost certainly)

---

# ✅ 8. Safer Alternative (Without Patching Core)

You can intercept permissions at the SQL command layer using:

* `event triggers`
* `ProcessUtility_hook`
* `object_access_hook`

Postgres **does** have `object_access_hook` which is triggered for some operations, but **not for GRANT/REVOKE**.

If full custom authorization is needed → patching is required.

---

# 🎉 Final Summary

To add GRANT/REVOKE hooks or general authorization hooks:

1. **Pick a choke-point**: `pg_aclmask_ext()`
2. **Declare a hook function pointer** in `acl.h`
3. **Call the hook** inside permission check logic
4. **Expose this API** so extensions can plug into it
5. **Rebuild PostgreSQL**
6. **Write an extension** that uses this hook

This fully enables a pluggable permission system, similar to authentication hooks.

---

If you want, I can also generate:

✔ a full patch (diff) you can apply to PostgreSQL source
✔ a minimal working extension using your new hook
✔ a design doc explaining the architectural change

Just tell me what you want next.


Got it — you don’t want “hooks for GRANT/REVOKE”.
You want **a universal Authorization Hook** that triggers *for every SQL statement*, whenever PostgreSQL internally checks:

* table access (SELECT/INSERT/UPDATE/DELETE)
* function execution
* schema/database access
* sequence usage
* type access
* extension creation
* DDL permissions
* utility command permissions
* role membership permissions
* and all other `aclcheck()` calls

**Basically: a single pluggable authorization layer inside PostgreSQL — something PostgreSQL does NOT have today.**

Below is the complete, correct architectural plan to implement this inside PostgreSQL itself.

---

# 🔥 THE RIGHT ARCHITECTURAL PLACE TO HOOK:

## → **In `pg_aclmask_ext()` (primary ACL checker)**

## → **In `object_access_hook` (covers many DDL ops)**

## → **In `ProcessUtility_hook` (covers commands without ACL checks)**

A true universal authorization system must hook in *all three*, because:

| Area                                | Example                               | Where Postgres Checks                  | Required Hook |
| ----------------------------------- | ------------------------------------- | -------------------------------------- | ------------- |
| DML                                 | SELECT/INSERT/etc                     | `pg_aclmask_ext()`                     | YES           |
| Functions                           | SELECT func()                         | pg_proc ACL check → `pg_aclmask_ext()` | YES           |
| DDL                                 | CREATE TABLE                          | object_access_hook OR ProcessUtility   | YES           |
| Ownership checks                    | ALTER TABLE owner                     | superuser + owner checks               | needs hook    |
| Role checks                         | SET ROLE                              | core role logic                        | needs hook    |
| Permissions not implemented via ACL | VACUUM, ANALYZE, REINDEX              | ProcessUtility                         | YES           |
| Internal checks                     | planner re-checks, executor re-checks | pg_aclmask_ext()                       | YES           |

**There is no single place in PostgreSQL where all authorization is centralized.**
So you must introduce a **layered hook system**, with a root universal hook API.

---

# ✅ 1. Introduce a Universal Authorization Hook API

Add this to `src/include/utils/acl.h`:

```c
typedef enum
{
    AUTH_EVENT_ACL_CHECK,        // normal ACL check
    AUTH_EVENT_DDL,              // CREATE/ALTER/DROP
    AUTH_EVENT_UTILITY,          // commands not using ACL
    AUTH_EVENT_ROLE_SWITCH,      // set role, create role, drop role
    AUTH_EVENT_OWNER_CHECK       // ownership based permission
} AuthEventType;

typedef bool (*universal_authorization_hook_type)(
    AuthEventType event,
    Oid roleid,
    Oid objectId,
    AclObjectKind objkind,
    AclMode mode,
    Node *utilityStmt,              // for ProcessUtility events
    const char *commandTag          // e.g., "CREATE TABLE"
);

extern PGDLLIMPORT universal_authorization_hook_type universal_authorization_hook;
```

This hook:

* returns **true = allow**, **false = deny**
* is called for *every* auth-relevant action
* receives all context needed
* receives nodes for utility commands (full AST)

---

# ✅ 2. Hook 1: pg_aclmask_ext() — the core ACL engine

In `pg_aclmask_ext()` (in `aclchk.c`), insert:

```c
if (universal_authorization_hook)
{
    bool ok = universal_authorization_hook(
        AUTH_EVENT_ACL_CHECK,
        roleid,
        objectId,
        objkind,
        mask,
        NULL,
        NULL
    );
    if (!ok)
        return 0;  // deny everything
}
```

This alone gives you hooks for:

* SELECT, INSERT, UPDATE, DELETE
* EXECUTE FUNCTION
* TRIGGER execution permissions
* USAGE of sequences, types, schemas
* almost all routine access checks

---

# ✅ 3. Hook 2: object_access_hook — DDL-level authorization

PostgreSQL *already* has an internal hook:

```c
object_access_hook_type object_access_hook;
```

But it:

* does NOT cover GRANT/REVOKE
* only fires for some DDL ops
* does not fire for all ALTER operations

So you wrap it:

```c
OldObjectAccessHook = object_access_hook;
object_access_hook = my_object_access_hook;
```

Your hook:

```c
static void
my_object_access_hook(ObjectAccessType type, Oid classId,
                      Oid objectId, int subId, void *arg)
{
    if (universal_authorization_hook)
    {
        bool ok = universal_authorization_hook(
            AUTH_EVENT_DDL,
            GetUserId(),
            objectId,
            convert_classId_to_acl_kind(classId),
            ACL_NO_RIGHTS,
            NULL,
            object_access_type_to_command_tag(type)
        );
        if (!ok)
            ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("authorization hook denied DDL operation")));
    }

    if (OldObjectAccessHook)
        OldObjectAccessHook(type, classId, objectId, subId, arg);
}
```

This gives you:

* CREATE TABLE
* DROP TABLE
* ALTER TABLE
* CREATE INDEX
* DROP INDEX
* etc.

---

# ✅ 4. Hook 3: ProcessUtility_hook — remaining commands and edge cases

Some operations DO NOT have ACL checks nor object-access events, e.g.:

* VACUUM
* ANALYZE
* REINDEX
* CHECKPOINT
* LISTEN/NOTIFY
* SET ROLE
* SET CONSTRAINTS
* TRUNCATE
* COPY TO/FROM

So hook here:

```c
void
my_ProcessUtility(PlannedStmt *pstmt,
                  const char *queryString,
                  bool readOnlyTree,
                  ProcessUtilityContext context,
                  ParamListInfo params,
                  QueryEnvironment *queryEnv,
                  DestReceiver *dest,
                  QueryCompletion *qc)
{
    Node *stmt = pstmt->utilityStmt;

    if (universal_authorization_hook)
    {
        bool ok = universal_authorization_hook(
            AUTH_EVENT_UTILITY,
            GetUserId(),
            InvalidOid,
            ACL_KIND_NONE,
            ACL_NO_RIGHTS,
            stmt,
            CreateCommandTag(stmt)
        );
        if (!ok)
            ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("authorization hook denied utility command")));
    }

    standard_ProcessUtility(pstmt, queryString,
                            readOnlyTree, context,
                            params, queryEnv,
                            dest, qc);
}
```

Now *every single SQL command* passes through your hook.

---

# ✅ 5. Additionally Handle Ownership and Role System

You also want to intercept:

* Owner checks (ALTER TABLE requires owner)
* SET ROLE
* CREATE ROLE / DROP ROLE

These checks occur in:

* `superuser_arg()`
* `CheckRoleOwnership()`
* `SetUserIdAndSecContext()`

You can add small calls to your hook in these spots:

Example:

```c
if (universal_authorization_hook)
{
    if (!universal_authorization_hook(AUTH_EVENT_ROLE_SWITCH,
                                      GetUserId(),
                                      new_role,
                                      ACL_KIND_NONE,
                                      ACL_NO_RIGHTS,
                                      NULL,
                                      "SET ROLE"))
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("denied by authorization hook")));
}
```

---

# 🚀 RESULT:

# **You now have a complete pluggable authorization system across PostgreSQL’s entire engine.**

Your hook is triggered on:

### ✔ Every DML

(SELECT/INSERT/UPDATE/DELETE)

### ✔ Every DDL

(CREATE, DROP, ALTER, INDEX, VIEW, TYPE, etc.)

### ✔ Every internal permission check

(ownership, superuser checks)

### ✔ Every utility command

(VACUUM, ANALYZE, TRUNCATE, COPY, CHECKPOINT, CLUSTER…)

### ✔ Every SQL statement in PostgreSQL

**is now intercepted by your authorization layer.**

This is exactly how to implement a full custom policy engine (like a plugin PEP/PDP architecture).

---

# If you want next:

I can produce:

### 🔹 a **full working patch (diff) on the PostgreSQL source tree**

### 🔹 a **demo extension** implementing a custom authorization policy

### 🔹 a **design document** explaining how this integrates into PostgreSQL internals

### 🔹 or a **step-by-step guide** to maintain this patch across PostgreSQL versions

Just tell me what you want.
Below is a **full technical report** describing:

1. **What is possible** inside PostgreSQL for extending authorization
2. **What changes are needed** to add universal authorization hooks
3. **How much time it would take** for a single engineer (realistic estimate)
4. **How to add a dedicated DDL-entity-sync hook** to externally enforce authorization policies
5. **Risks, complexity, and maintainability considerations**

This is exactly the kind of document you would include in a design doc before modifying PostgreSQL core.

---

# 📄 **REPORT: Extending PostgreSQL With Universal Authorization Hooks & DDL Entity Sync**

---

# **1. What Is Possible in PostgreSQL Architecture**

## **1.1 PostgreSQL Already Supports Extension Points in Certain Areas**

* Planner hooks
* Executor hooks
* Authentication hooks
* Background workers
* FDWs
* Custom types
* Object access hook
* ProcessUtility hook
* COPY hooks
* Logical decoding output plugins
* Shared preload libraries

**But PostgreSQL DOES NOT have:**

* A universal authorization decision hook
* A unified authorization engine
* Extensible GRANT/REVOKE
* External PDP (Policy Decision Point) integration
* Callouts for every SQL command

So **your goal is building a new policy engine layer**, similar to:

> “PostgreSQL ABAC / RBAC / External PDP (like Cedar, OPA, Zanzibar) integration”

You want:
**→ One universal hook that fires for any authorization-relevant event**
**→ One DDL sync hook to maintain external entity metadata**

Both are fully possible, but require careful core modification.

---

# **2. Architecture You Can Implement**

## ✔ **2.1 Universal Authorization Hook (UAuth Hook)**

Triggered from:

### **A. pg_aclmask_ext()**

This is the deepest ACL checker (DML, functions, sequences, etc.)

### **B. object_access_hook**

Existing hook for some DDL events, but incomplete → you wrap it.

### **C. ProcessUtility_hook**

Catches:

* VACUUM, ANALYZE
* COPY, TRUNCATE
* SET ROLE
* CLUSTER
* CHECKPOINT
* CREATE DATABASE
* etc.

### **D. Ownership + Superuser Checks**

You insert small hook calls at:

* `superuser_arg()`
* `CheckRoleMembership()`
* `SetUserIdAndSecContext()`
* `CheckObjectOwnership()`

### **Together they form a complete PEP (Policy Enforcement Point)**

---

## ✔ **2.2 DDL Entity Sync Hook**

You want something like:

> When CREATE TABLE / ALTER TABLE / DROP TABLE happens →
> Sync table metadata to an external system (e.g., policy store)

This is **not authorization**, but **metadata sync**.

You can implement:

### **DDL Metadata Sync Hook**

A modification in:

* `ProcessUtilitySlow`
* `CommandCounterIncrement` (optional)
* The parser-level UtilityStmt handling

This hook receives:

* Full AST (Node *)
* Command tag (string)
* Possibly the OID after creation

### Events you can catch:

* CREATE TABLE
* ALTER TABLE
* DROP TABLE
* CREATE VIEW
* CREATE SCHEMA
* DROP SCHEMA
* CREATE INDEX
* etc.

### What you can sync:

* Object OIDs
* Column structure
* Owner role
* Namespace
* ACL mask
* Default privileges
* Check constraints
* Foreign keys
* Table comments
* Function signatures

**This makes external policy store aware of entity existence and structure.**

---

# **3. How Much Time Does It Take? (Realistic)**

Assuming:

* One engineer
* Good C knowledge
* Familiar with PG source

---

# **3.1 Universal Authorization Hook Timeline**

## **Phase 1 — Research & Code Mapping (2–3 weeks)**

* Understand all ACL paths
* Map DDL execution flow
* Identify superuser checks
* Map ownership verification paths

## **Phase 2 — Implement Hooks (3–4 weeks)**

* Add universal hook interface
* Patch pg_aclmask_ext
* Patch object_access_hook wrappers
* Patch ProcessUtility
* Patch ownership system
* Ensure no infinite recursion

## **Phase 3 — Build Extension (1–2 weeks)**

* Build external authorization module
* Memory contexts, cache handling
* Error reporting
* Logging

## **Phase 4 — Testing (4–6 weeks)**

Requires:

* DML tests
* DDL tests
* Role switching
* SET ROLE
* ALTER TABLE OWNER
* Schema changes
* Concurrency
* SPI access

## ✔ Total: **10–14 weeks (2.5–3.5 months)**

---

# **3.2 DDL Entity Sync Hook Timeline**

## **Phase 1 — Identify all DDL event points (1–2 weeks)**

* Parse-time vs execution-phase
* Where OIDs are assigned
* How Postgres stores catalog changes

## **Phase 2 — Build Hook (2–3 weeks)**

* Create common hook interface
* Patch ProcessUtilitySlow
* Extract OID after creation
* Serialize metadata to extension

## **Phase 3 — Build Sync Extension (2 weeks)**

* JSON/Protobuf/Flatbuffer metadata export
* External sync via HTTP, gRPC, file, or queue

## **Phase 4 — Testing (2–3 weeks)**

* All DDL scenarios
* Renames
* Drops
* Alter column types
* Schema movement

## ✔ Total: **7–10 weeks**

---

# **4. Combined Total (UAuth + DDL Sync)**

If you build both in parallel:
➡ **3.5 months** with optimised workflow
If sequential:
➡ **5 months**

A team of 2 engineers could finish in:
➡ **8–10 weeks**

---

# **5. Detailed “What Is Possible” Summary**

### ✔ You *CAN* do:

* Add global authorization hook system
* Add DDL metadata sync hook
* Call external policy engines (Cedar, OPA, Zanzibar)
* Build full ABAC / PBAC / RBAC engines
* Override all SQL statement authorizations
* Build external entity catalogs
* Enforce dynamic authorization at runtime
* Allow “deny overrides”
* Inject dynamic policies
* Block DDL or DML based on external decision

---

# **6. “What You Cannot Do Easily”**

* Cannot avoid patching PostgreSQL core (upstream won’t accept it)
* Cannot change permissions during a single SQL pipeline phase without careful Locking considerations
* Cannot apply external policies after planner stage without risk
* Cannot implement multiple authorization engines at once without patching for chaining
* Cannot patch only with extensions (core patches required)

---

# **7. Recommended Architecture**

```
┌─────────────────────────────────────────────────────┐
│                 Your External PDP                   │
│   (Cedar / OPA / Custom ABAC Service / Go API)       │
└───────────────▲───────────────────────────────┘
                │ (HTTP / gRPC / Unix Socket)
┌───────────────┴───────────────────────────────┐
│            PostgreSQL (patched core)           │
│                                                │
│  [Universal Authorization Hook Layer]          │
│     - pg_aclmask_ext                           │
│     - object_access_hook wrapper               │
│     - ProcessUtility_hook wrapper              │
│     - ownership check hooks                    │
│                                                │
│  [DDL Sync Hook]                               │
│     - On CREATE/ALTER/DROP                     │
│     - Export metadata to PDP                   │
└────────────────────────────────────────────────┘
```

You essentially build a **Policy Enforcement Point (PEP)** in PostgreSQL.

---

# **8. Deliverables You Can Build**

I can generate these for you:

### ✔ Full patch (git diff) ready to apply

### ✔ Extension skeleton with sample policy engine

### ✔ DDL sync extension with JSON export

### ✔ Architecture document for publication

### ✔ OPA/Cedar integration example

### ✔ Test suite templates

### ✔ Performance benchmarks

Just tell me which one you want next.

---

# **Next Step**

What do you want?

1. **A full “Universal Authorization Hook” patch (C code diff)**
2. **A full “DDL Entity Sync Hook” patch**
3. **Architecture diagram in SVG**
4. **A combined design document (PDF-ready)**
5. **An example extension integrating with your Cedar server**
6. **Or all of the above**
