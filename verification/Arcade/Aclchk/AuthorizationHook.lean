import Std.Tactic.BVDecide
import Arcade.Aclchk.Types

/-! # Model of `src/include/utils/authorization_hook.h`

The header declares the data the core passes to the hook, plus five helpers
whose bodies live in aclchk.c:90–205.

This file models the full `AuthorizationInfo` structure, and connects it to the
smaller `AuthInfo` used by `Env.hook` in the aclchk.c model. The refinement
theorems at the end show that using `AuthInfo` loses nothing: any hook over the
full C structure is equivalent, on every call the core makes, to a hook over
`AuthInfo`.

Abstractions:
* Strings (`const char *`) are `Option String`, with `none` = NULL.
* `Bitmapset *` is a `List Int` of attribute numbers (a NULL bitmapset is empty).
* `Node *parse_tree` is `Option Unit`: only NULL / non-NULL is modelled.
* The hook receives a non-const pointer, so a C hook could modify the struct.
  The core never reads it after the call except in `FreeAuthorizationInfo`,
  so the model treats the hook as a pure function.
* `FreeAuthorizationInfo` only releases memory and is not modelled.
-/

namespace Arcade.Aclchk

/-! ## Types (authorization_hook.h:33–108) -/

/-- `AuthorizationEventType` (lines 33–41). -/
inductive EventType where
  | dml | ddl | utility | objectAccess | roleCheck | aclCheck
  deriving DecidableEq, Repr

/-- `PgAuthDMLInfo` (lines 56–65). -/
structure DMLInfo where
  relid         : Oid
  relname       : Option String
  schemaname    : Option String
  requiredPerms : AclMode
  selectedCols  : List Int
  insertedCols  : List Int
  updatedCols   : List Int
  deriving DecidableEq, Repr

/-- `PgAuthDDLInfo` (lines 70–81). `classid = none` is InvalidOid (0). -/
structure DDLInfo where
  classid       : Option ClassId
  objectid      : Oid
  objectname    : Option String
  schemaname    : Option String
  parseTree     : Option Unit
  commandTag    : Option String
  subid         : Int
  isInternal    : Bool
  requiredPerms : AclMode
  deriving DecidableEq, Repr

/-- `PgAuthDDLInfo` after `memset(…, 0, …)`: every field zero or NULL. -/
def DDLInfo.zero : DDLInfo :=
  ⟨none, 0, none, none, none, none, 0, false, 0⟩

/-- `PgAuthDMLInfo` after `memset(…, 0, …)`. -/
def DMLInfo.zero : DMLInfo :=
  ⟨0, none, none, 0, [], [], []⟩

/-- The anonymous `union { dml; ddl; } info` (lines 102–106).
    The constructor records which member was last written; `zeroed` is the
    state right after `memset`, where every member reads as all-zero. -/
inductive InfoUnion where
  | zeroed
  | dml (d : DMLInfo)
  | ddl (d : DDLInfo)
  deriving DecidableEq, Repr

/-- Reading `info.ddl`. `none` means the bytes belong to the other member:
    reading them as DDL would be type confusion. -/
def InfoUnion.readDDL : InfoUnion → Option DDLInfo
  | .zeroed => some DDLInfo.zero
  | .ddl d  => some d
  | .dml _  => none

/-- Reading `info.dml`. -/
def InfoUnion.readDML : InfoUnion → Option DMLInfo
  | .zeroed => some DMLInfo.zero
  | .dml d  => some d
  | .ddl _  => none

/-- Writing fields of `info.ddl`: start from the current DDL view
    (all-zero if the union was just cleared). -/
def InfoUnion.writeDDL (u : InfoUnion) (f : DDLInfo → DDLInfo) : InfoUnion :=
  .ddl (f ((u.readDDL).getD DDLInfo.zero))

/-- `AuthorizationInfo` (lines 86–108). -/
structure AuthorizationInfo where
  eventType   : EventType
  roleid      : Oid
  rolename    : Option String
  dboid       : Oid
  dbname      : Option String
  queryString : Option String
  info        : InfoUnion
  deriving DecidableEq, Repr

/-- `universal_authorization_hook_type` (lines 123–124). -/
abbrev FullHook := AuthorizationInfo → HookResult

/-! ## Helpers (bodies in aclchk.c:100–205) -/

/-- `InitAuthorizationInfo` (aclchk.c:100–120): memset to zero, set the event
    type and role, look up the role name and the current database. -/
def initAuthorizationInfo (e : Env) (ev : EventType) (roleid : Oid) : AuthorizationInfo where
  eventType   := ev
  roleid      := roleid
  rolename    := e.cat.roleName roleid                 -- 109–116
  dboid       := e.myDb                                -- 118
  dbname      := e.cat.dbName e.myDb                   -- 119
  queryString := none                                  -- left NULL by memset
  info        := .zeroed                               -- memset (105)

/-- What every hook block in aclchk.c builds before calling the hook
    (e.g. aclchk.c:3331–3334 and 3498–3502). `subid` is only set at the column
    call site; elsewhere it stays 0 from memset, which is what passing `0` models. -/
def buildHookInfo (e : Env) (role : Oid) (c : ClassId) (obj : Oid) (subid : Int)
    (mask : AclMode) : AuthorizationInfo :=
  let base := initAuthorizationInfo e .aclCheck role
  { base with info := base.info.writeDDL fun d =>
      { d with classid := some c, objectid := obj, subid := subid, requiredPerms := mask } }

/-- `GetAuthorizationEventTypeName` (aclchk.c:131–151). The C `default:` branch
    returns "UNKNOWN"; it is unreachable for valid enum values. -/
def EventType.name : EventType → String
  | .dml          => "DML"
  | .ddl          => "DDL"
  | .utility      => "UTILITY"
  | .objectAccess => "OBJECT_ACCESS"
  | .roleCheck    => "ROLE_CHECK"
  | .aclCheck     => "ACL_CHECK"

/-- `GetAuthorizationResultName` (aclchk.c:153–167). -/
def HookResult.name : HookResult → String
  | .grant  => "GRANT"
  | .deny   => "DENY"
  | .ignore => "IGNORE"

/-- The bit/name pairs `AclModeToPrivilegeString` tests, in C order (aclchk.c:176–199). -/
def privilegeTable : List (AclMode × String) :=
  [ (ACL_INSERT, "INSERT"), (ACL_SELECT, "SELECT"), (ACL_UPDATE, "UPDATE"),
    (ACL_DELETE, "DELETE"), (ACL_TRUNCATE, "TRUNCATE"), (ACL_REFERENCES, "REFERENCES"),
    (ACL_TRIGGER, "TRIGGER"), (ACL_EXECUTE, "EXECUTE"), (ACL_USAGE, "USAGE"),
    (ACL_CREATE, "CREATE"), (ACL_CREATE_TEMP, "TEMPORARY"), (ACL_CONNECT, "CONNECT") ]

/-- One `appendStringInfo(&buf, "%sNAME", buf.len > 0 ? ", " : "")`. -/
def appendPriv (buf name : String) : String :=
  buf ++ (if buf.length > 0 then ", " else "") ++ name

/-- `AclModeToPrivilegeString` (aclchk.c:169–205). -/
def aclModeToPrivilegeString (m : AclMode) : String :=
  let buf := privilegeTable.foldl
    (fun buf p => if (m &&& p.1) != 0 then appendPriv buf p.2 else buf) ""
  if buf.length = 0 then "NONE" else buf                  -- 201–202

/-! ## Theorems: InitAuthorizationInfo -/

theorem init_eventType (e : Env) (ev : EventType) (r : Oid) :
    (initAuthorizationInfo e ev r).eventType = ev := rfl

theorem init_roleid (e : Env) (ev : EventType) (r : Oid) :
    (initAuthorizationInfo e ev r).roleid = r := rfl

/-- memset leaves the query string NULL: the hook never sees the SQL text. -/
theorem init_queryString_null (e : Env) (ev : EventType) (r : Oid) :
    (initAuthorizationInfo e ev r).queryString = none := rfl

/-! ## Theorems: what the core passes to the hook -/

/-- The core only ever emits `PG_AUTH_EVENT_ACL_CHECK`. The other five event
    types are never produced, so the extension's DML/DDL/UTILITY branches are
    unreachable from this patch. -/
theorem build_eventType (e : Env) (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m : AclMode) :
    (buildHookInfo e role c obj s m).eventType = .aclCheck := rfl

/-- The union holds the DDL member, with exactly the fields the call site set
    and everything else zero/NULL from memset. -/
theorem build_readDDL (e : Env) (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m : AclMode) :
    (buildHookInfo e role c obj s m).info.readDDL =
      some { DDLInfo.zero with classid := some c, objectid := obj, subid := s, requiredPerms := m } := rfl

/-- Reading `info.dml` on anything the core builds is type confusion. -/
theorem build_readDML_invalid (e : Env) (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m : AclMode) :
    (buildHookInfo e role c obj s m).info.readDML = none := rfl

/-- `objectname`, `schemaname` and `command_tag` are always NULL: the hook must
    resolve names itself from the OIDs. -/
theorem build_names_null (e : Env) (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m : AclMode)
    (d : DDLInfo) (hd : (buildHookInfo e role c obj s m).info.readDDL = some d) :
    d.objectname = none ∧ d.schemaname = none ∧ d.commandTag = none := by
  rw [build_readDDL] at hd
  cases hd
  exact ⟨rfl, rfl, rfl⟩

/-! ## Refinement: `AuthInfo` is a faithful abstraction -/

/-- Read the `AuthInfo` view out of a full `AuthorizationInfo`. -/
def AuthorizationInfo.toAuthInfo (a : AuthorizationInfo) : Option AuthInfo :=
  match a.info.readDDL with
  | some d =>
    match d.classid with
    | some c => some ⟨a.roleid, c, d.objectid, d.subid, d.requiredPerms⟩
    | none   => none
  | none => none

/-- Rebuild the full structure the core would pass, from an `AuthInfo`. -/
def AuthInfo.toFull (e : Env) (i : AuthInfo) : AuthorizationInfo :=
  buildHookInfo e i.roleid i.classid i.objectid i.subid i.required

/-- Projecting what the core builds gives exactly the `AuthInfo` used in the
    aclchk.c model (e.g. `⟨role, .relation, table, 0, mask⟩` in `pgClassAclmask`). -/
theorem build_toAuthInfo (e : Env) (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m : AclMode) :
    (buildHookInfo e role c obj s m).toAuthInfo = some ⟨role, c, obj, s, m⟩ := rfl

/-- Round trip: the full structure is determined by its `AuthInfo` view
    and the environment. -/
theorem toFull_build (e : Env) (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m : AclMode) :
    AuthInfo.toFull e ⟨role, c, obj, s, m⟩ = buildHookInfo e role c obj s m := rfl

/-- **Hook factorization.** Any hook over the full C structure behaves, on every
    call the core makes, like a hook over `AuthInfo`. This justifies the type of
    `Env.hook`: proving a property for all `AuthInfo → HookResult` covers every
    real C hook. -/
theorem hook_factors (e : Env) (full : FullHook) :
    ∃ h : AuthInfo → HookResult, ∀ role c obj s m,
      full (buildHookInfo e role c obj s m) = h ⟨role, c, obj, s, m⟩ :=
  ⟨fun i => full (i.toFull e), fun _ _ _ _ _ => rfl⟩

/-! ## Theorems: name helpers -/

/-- Event names are distinct, so log lines identify the event unambiguously. -/
theorem EventType.name_injective (a b : EventType) (h : a.name = b.name) : a = b := by
  cases a <;> cases b <;> simp_all [EventType.name]

theorem HookResult.name_injective (a b : HookResult) (h : a.name = b.name) : a = b := by
  cases a <;> cases b <;> simp_all [HookResult.name]

/-- The C `"UNKNOWN"` default is never produced for a valid value. -/
theorem EventType.name_ne_unknown (a : EventType) : a.name ≠ "UNKNOWN" := by
  cases a <;> decide

theorem HookResult.name_ne_unknown (a : HookResult) : a.name ≠ "UNKNOWN" := by
  cases a <;> decide

/-! ## Theorems: AclModeToPrivilegeString -/

/-- OR of every bit `AclModeToPrivilegeString` knows how to print. -/
def printableBits : AclMode := privilegeTable.foldl (fun acc p => acc ||| p.1) 0

/-- A left fold that never changes its accumulator returns the start value. -/
theorem foldl_skip {α β} (f : β → α → β) (b : β) (l : List α) (h : ∀ x ∈ l, f b x = b) :
    l.foldl f b = b := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.foldl]
    rw [h x (by simp)]
    exact ih (fun y hy => h y (by simp [hy]))

/-- A mask with none of the 12 printable bits is logged as "NONE". -/
theorem privString_none_of_no_bits (m : AclMode) (hm : m &&& printableBits = 0) :
    aclModeToPrivilegeString m = "NONE" := by
  unfold aclModeToPrivilegeString
  rw [foldl_skip]
  · rfl
  · intro p hp
    have h0 : m &&& p.1 = 0 := by
      simp only [privilegeTable, List.mem_cons, List.not_mem_nil, or_false] at hp
      simp only [printableBits, privilegeTable, List.foldl] at hm
      rcases hp with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;>
        simp only [ACL_INSERT, ACL_SELECT, ACL_UPDATE, ACL_DELETE, ACL_TRUNCATE, ACL_REFERENCES,
          ACL_TRIGGER, ACL_EXECUTE, ACL_USAGE, ACL_CREATE, ACL_CREATE_TEMP, ACL_CONNECT] at hm ⊢ <;>
        bv_decide
    simp [h0]

theorem privString_select_insert :
    aclModeToPrivilegeString (ACL_SELECT ||| ACL_INSERT) = "INSERT, SELECT" := by
  decide

/-- **Finding**: `ACL_SET`, `ACL_ALTER_SYSTEM` and `ACL_MAINTAIN` are not in the
    table, so a mask holding only those bits is logged as "NONE". -/
theorem privString_maintain_is_none :
    aclModeToPrivilegeString ACL_MAINTAIN = "NONE" := by
  decide

end Arcade.Aclchk
