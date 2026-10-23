import Arcade.Plugin.Cache

/-! # Entity sync (pg_authorization.c:602–805, 1121–1260)

DDL fires `object_access_hook` and `ProcessUtility_hook`; the plugin turns
them into PUT/DELETE requests on the agent's entity store, resetting the
authorization cache first.

Modelled: which events produce which sync operations, the request body, the
cache reset, and which requests apply the TLS settings.

Names are what the plugin's syscache lookups return **when the hook runs**.
PostgreSQL often calls the hook before `CommandCounterIncrement`, so the
lookup still sees the catalog as it was before the change:
* after `CREATE ROLE` without members, the new role is not yet visible
  (user.c:486 inserts it, 492–493 only increments the counter for members,
  600 calls the hook), so the lookup fails;
* after a rename, the old name is still visible
  (tablecmds.c `RenameRelationInternal`: update, then the hook, no increment between).
A first version of this model assumed the post-change names; the TAP test
t/002_findings.pl showed otherwise, and the events below use the visible names.

HTTP success/failure only affects statistics, never the DDL itself.
-/

namespace Arcade.Plugin.Sync
open Arcade.Aclchk Arcade.Plugin

/-- `ObjectAccessType` values the hook distinguishes (1218–1226). -/
inductive Access where
  | postCreate | postAlter | drop | other
  deriving DecidableEq, Repr

/-- The catalog an object-access event is about (1135–1215). -/
inductive ObjClass where
  | relation (relkind : Char)
  | namespace | authid | database | procedure | other
  deriving DecidableEq, Repr

/-- One object-access event, with the names the plugin's lookups see when the hook runs. -/
structure ObjEvent where
  access : Access
  cls    : ObjClass
  name   : Option String     -- relname / nspname / rolname / datname / proname, as visible; `none` if the lookup fails
  schema : Option String     -- schema name, for relations and functions
  deriving DecidableEq, Repr

inductive SyncOp where
  | upsert (ty id : String)    -- cedar_sync_entity_upsert
  | delete (ty id : String)    -- cedar_sync_entity_delete
  deriving DecidableEq, Repr

def qualified (schema : Option String) (name : String) : String :=
  match schema with
  | some s => s ++ "." ++ name
  | none   => name

/-- The (entity type, entity id) for an event, if it is one the plugin syncs (1135–1215). -/
def entityOf (ev : ObjEvent) : Option (String × String) :=
  match ev.cls, ev.name with
  | .relation k, some n =>                                                  -- 1137–1170
    if k = 'r' ∨ k = 'v' ∨ k = 'm' ∨ k = 'p' then some ("Table", qualified ev.schema n) else none
  | .namespace, some n => some ("Schema", n)                                -- 1172–1181
  | .authid, some n    => some ("User", n)                                  -- 1183–1192
  | .database, some n  => some ("Database", n)                              -- 1194–1196
  | .procedure, some n => some ("Routine", qualified ev.schema n)           -- 1198–1209
  | _, _ => none

/-- `cedar_object_access_hook` (1121–1235): the sync operations an event causes. -/
def objectAccessSync (cfg : Config) (ev : ObjEvent) : List SyncOp :=
  if !cfg.enabled && !cfg.syncEnabled then []                               -- 1130–1131
  else if cfg.agentUrl = "" then []                                         -- 1133–1134
  else if !cfg.syncEnabled then []                                          -- 1136
  else match entityOf ev with
    | none => []
    | some (ty, id) =>
      match ev.access with
      | .postCreate | .postAlter => [.upsert ty id]                         -- 1218–1221
      | .drop                    => [.delete ty id]                         -- 1222–1224
      | .other                   => []

/-- Utility statements `cedar_process_utility_hook` also syncs (1238–1260). -/
inductive UtilityStmt where
  | createRole (name : String)
  | createSchema (name : String)
  | other
  deriving DecidableEq, Repr

def utilitySync (cfg : Config) (u : UtilityStmt) : List SyncOp :=
  if cfg.syncEnabled && cfg.agentUrl ≠ "" then
    match u with
    | .createRole n   => if n = "" then [] else [.upsert "User" n]
    | .createSchema n => if n = "" then [] else [.upsert "Schema" n]
    | .other          => []
  else []

/-- Each sync call resets the authorization cache first (616, 724). -/
def applyToCache (st : CacheState) (now : Nat) (ops : List SyncOp) : CacheState :=
  if ops = [] then st else resetCache st now

/-- The PUT body (659–662). -/
structure EntityBody where
  uidType : String
  uidId   : String
  attrs   : List (String × String)
  parents : List String
  deriving DecidableEq, Repr

def upsertBody (ty id : String) : EntityBody := ⟨ty, id, [], []⟩

/-- Whether the request calls `configure_curl_ssl` (416–450): the authorization
    request (539) and DELETE (779) do; the PUT in `cedar_sync_entity_upsert` does not. -/
def appliesTlsConfig : SyncOp → Bool
  | .upsert _ _ => false
  | .delete _ _ => true

/-! ## Theorems -/

def syncOn : Config := ⟨true, "http://cedar-agent:8180", true, 1024, 300000000, true⟩

theorem create_table_upserts :
    objectAccessSync syncOn ⟨.postCreate, .relation 'r', some "patient_records", some "public"⟩ =
      [.upsert "Table" "public.patient_records"] := by decide

theorem drop_table_deletes :
    objectAccessSync syncOn ⟨.drop, .relation 'r', some "patient_records", some "public"⟩ =
      [.delete "Table" "public.patient_records"] := by decide

/-- Indexes, sequences and other relation kinds are never synced. -/
theorem index_not_synced (acc : Access) (n s : Option String) :
    objectAccessSync syncOn ⟨acc, .relation 'i', n, s⟩ = [] := by
  cases n <;> simp [objectAccessSync, syncOn, entityOf]

/-- With sync disabled, no event produces a sync operation (so none resets the cache). -/
theorem sync_disabled (cfg : Config) (ev : ObjEvent) (h : cfg.syncEnabled = false) :
    objectAccessSync cfg ev = [] := by
  simp [objectAccessSync, h]

/-- Any event that does sync resets the cache. -/
theorem sync_resets_cache (st : CacheState) (now : Nat) (ops : List SyncOp) (h : ops ≠ []) :
    (applyToCache st now ops).lastReset = now := by
  simp [applyToCache, h, resetCache]

/-- **Finding**: synced entities never carry attributes or parents, so ABAC
    policies over entity attributes (e.g. `resource.department`) have nothing
    to read unless the agent's store is filled some other way. -/
theorem upsert_has_no_attributes (ty id : String) :
    (upsertBody ty id).attrs = [] ∧ (upsertBody ty id).parents = [] := ⟨rfl, rfl⟩

/-- **Finding**: renaming a table fires OAT_POST_ALTER while the old name is
    still visible, so the plugin re-sends the *old* entity and never sends the
    new name. The agent keeps an entity for a name that no longer exists and has
    none for the table's real name. (Confirmed by t/002_findings.pl, F6.) -/
theorem rename_resyncs_old_name :
    -- ALTER TABLE public.records RENAME TO records_v2: the hook still sees "records"
    objectAccessSync syncOn ⟨.postAlter, .relation 'r', some "records", some "public"⟩ =
      [.upsert "Table" "public.records"] := by decide

/-- **Finding**: the PUT request does not apply the TLS settings (client
    certificate, verification flags) that the other requests apply. -/
theorem upsert_skips_tls_config (ty id : String) :
    appliesTlsConfig (.upsert ty id) = false ∧ appliesTlsConfig (.delete ty id) = true := ⟨rfl, rfl⟩

/-- `CREATE ROLE` without members: the object-access hook cannot see the new
    role yet and syncs nothing; only the utility hook's PUT is sent.
    (Confirmed by t/002_findings.pl, F7. An earlier version of this theorem
    predicted two PUTs, from a model that assumed the role was visible.) -/
theorem create_role_synced_once :
    objectAccessSync syncOn ⟨.postCreate, .authid, none, none⟩ ++
      utilitySync syncOn (.createRole "alice") =
      [.upsert "User" "alice"] := by decide

end Arcade.Plugin.Sync
