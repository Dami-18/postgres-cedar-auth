/-! # Types for the aclchk.c model

Mirrors `src/include/utils/authorization_hook.h` and the parts of
`src/include/nodes/parsenodes.h` / `src/include/utils/acl.h` the patch uses.

Abstractions (things the C code calls that we do not verify) live in `Env`:
native `aclmask()`, `superuser_arg()`, syscache catalog lookups, and the hook.
-/

namespace Arcade.Aclchk

/-- `AclMode` is `uint64` in PostgreSQL 17. -/
abbrev AclMode := BitVec 64
abbrev Oid := Nat

/-! ## ACL bits (parsenodes.h:76–90) -/
def ACL_INSERT       : AclMode := 1#64 <<< 0
def ACL_SELECT       : AclMode := 1#64 <<< 1
def ACL_UPDATE       : AclMode := 1#64 <<< 2
def ACL_DELETE       : AclMode := 1#64 <<< 3
def ACL_TRUNCATE     : AclMode := 1#64 <<< 4
def ACL_REFERENCES   : AclMode := 1#64 <<< 5
def ACL_TRIGGER      : AclMode := 1#64 <<< 6
def ACL_EXECUTE      : AclMode := 1#64 <<< 7
def ACL_USAGE        : AclMode := 1#64 <<< 8
def ACL_CREATE       : AclMode := 1#64 <<< 9
def ACL_CREATE_TEMP  : AclMode := 1#64 <<< 10
def ACL_CONNECT      : AclMode := 1#64 <<< 11
def ACL_SET          : AclMode := 1#64 <<< 12
def ACL_ALTER_SYSTEM : AclMode := 1#64 <<< 13
def ACL_MAINTAIN     : AclMode := 1#64 <<< 14

/-- `ACL_ALL_RIGHTS_SCHEMA` (acl.h:169). -/
def ACL_ALL_RIGHTS_SCHEMA : AclMode := ACL_USAGE ||| ACL_CREATE

/-- `AclMaskHow`: `ACLMASK_ALL` or `ACLMASK_ANY`. -/
inductive How where
  | all | any
  deriving DecidableEq, Repr

/-- `AuthorizationResult` (authorization_hook.h). -/
inductive HookResult where
  | grant | deny | ignore
  deriving DecidableEq, Repr

/-- The catalog OIDs the patch passes as `classid`. -/
inductive ClassId where
  | relation | namespace | type | database | procedure | other
  deriving DecidableEq, Repr

/-- The fields of `AuthorizationInfo` that the hook block sets
    (`roleid` via `InitAuthorizationInfo`, the rest via `info.ddl.*`). -/
structure AuthInfo where
  roleid   : Oid
  classid  : ClassId
  objectid : Oid
  subid    : Int        -- C `int`; negative for system columns
  required : AclMode
  deriving DecidableEq, Repr

/-- Which catalog entry's ACL native `aclmask()` reads. -/
structure AclKey where
  classid  : ClassId
  objectid : Oid
  subid    : Int
  deriving DecidableEq, Repr

/-- The pg_class fields `pg_class_aclmask_ext` reads. -/
structure ClassRow where
  isSystem : Bool    -- IsSystemClass()
  isView   : Bool    -- relkind = RELKIND_VIEW
  deriving Repr

/-- The pg_attribute fields `pg_attribute_aclmask_ext` reads. -/
structure AttRow where
  dropped : Bool     -- attisdropped
  aclNull : Bool     -- attacl IS NULL
  deriving Repr

/-- Syscache lookups. `none` / `false` = tuple not found. -/
structure Catalog where
  classRow    : Oid → Option ClassRow
  attRow      : Oid → Int → Option AttRow
  nspFound    : Oid → Bool
  isTempNsp   : Oid → Bool
  /-- OID whose ACL a type uses after following array element / multirange
      range types (aclchk.c:4075–4126); `none` if a lookup fails. -/
  typeAclOid  : Oid → Option Oid
  objFound    : ClassId → Oid → Bool
  /-- pg_authid.rolname via SearchSysCache1(AUTHOID); `none` if not found. -/
  roleName    : Oid → Option String
  /-- get_database_name(); `none` (NULL) if not found. -/
  dbName      : Oid → Option String

/-- Everything the patched functions call but we do not model. -/
structure Env where
  superuser : Oid → Bool                                -- superuser_arg()
  aclmask   : AclKey → Oid → AclMode → How → AclMode    -- native aclmask(acl, roleid, owner, mask, how)
  hook      : Option (AuthInfo → HookResult)            -- universal_authorization_hook (none = NULL)
  cat       : Catalog
  myDb      : Oid                                       -- MyDatabaseId

/-- Assumption about native PostgreSQL: `aclmask()` never returns bits outside
    `mask`. Justify by reading `aclmask()` in src/backend/utils/adt/acl.c. -/
def Env.WellFormed (e : Env) : Prop :=
  ∀ k r m h, e.aclmask k r m h &&& ~~~m = 0

end Arcade.Aclchk
