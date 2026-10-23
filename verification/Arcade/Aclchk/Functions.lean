import Std.Tactic.BVDecide
import Arcade.Aclchk.HookBlock

/-! # Layer 2 and 3: the five patched functions and the dispatch

One wrapper per C function, keeping each function's early exits in C order.

Abstractions in this file:
* `is_missing` is treated as non-NULL: a missing object returns 0 instead of
  raising ERROR. Both deny, so this is safe for the security theorems.
* Built-in roles (`pg_read_all_data`, `pg_write_all_data`, `pg_maintain`;
  aclchk.c:3628–3653, 3987–3990) are left out for now. Add them later as an
  `Env` field and re-run the proofs.
* Memory management (`pfree`, `ReleaseSysCache`) and ACL detoasting are not modelled.
-/

namespace Arcade.Aclchk

/-! ## Layer 2 -/

/-- Bits stripped for system catalogs (aclchk.c:3573–3577):
    ACL_INSERT | ACL_UPDATE | ACL_DELETE | ACL_TRUNCATE | ACL_USAGE. -/
def catalogWriteBits : AclMode :=
  ACL_INSERT ||| ACL_UPDATE ||| ACL_DELETE ||| ACL_TRUNCATE ||| ACL_USAGE

/-- `pg_class_aclmask_ext` (aclchk.c:3533–3693). -/
def pgClassAclmask (e : Env) (table role : Oid) (mask : AclMode) (how : How) :
    AclMode × Option AuthInfo :=
  match e.cat.classRow table with
  | none => (0, none)                                                    -- 3547–3555
  | some r =>
    let mask :=                                                          -- 3573–3577
      if (mask &&& catalogWriteBits) != 0 && r.isSystem && !r.isView && !e.superuser role
      then mask &&& ~~~catalogWriteBits else mask
    if e.superuser role then (mask, none)                                -- 3582–3586
    else
      let result := e.aclmask ⟨.relation, table, 0⟩ role mask how         -- 3615
      hookBlock e ⟨role, .relation, table, 0, mask⟩ result mask how      -- 3655–3690

/-- `pg_attribute_aclmask_ext` (aclchk.c:3371–3517). No superuser check here. -/
def pgAttributeAclmask (e : Env) (table : Oid) (attnum : Int) (role : Oid)
    (mask : AclMode) (how : How) : AclMode × Option AuthInfo :=
  match e.cat.attRow table attnum with
  | none => (0, none)                                                    -- 3387–3397
  | some a =>
    if a.dropped then (0, none)                                          -- 3408–3416
    else if a.aclNull then (0, none)                                     -- 3432–3436
    else match e.cat.classRow table with
      | none => (0, none)                                                -- 3445–3454
      | some _ =>
        let result := e.aclmask ⟨.relation, table, attnum⟩ role mask how  -- 3470
        hookBlock e ⟨role, .relation, table, attnum, mask⟩ result mask how  -- 3478–3514

/-- The non-dispatching part of `object_aclmask_ext` (aclchk.c:3259–3346),
    for classids other than namespace and type. -/
def objectAclmaskBase (e : Env) (classid : ClassId) (obj role : Oid)
    (mask : AclMode) (how : How) : AclMode × Option AuthInfo :=
  if e.superuser role then (mask, none)                                  -- 3260–3261
  else if !e.cat.objFound classid obj then (0, none)                     -- 3269–3277
  else
    let result := e.aclmask ⟨classid, obj, 0⟩ role mask how               -- 3303
    hookBlock e ⟨role, classid, obj, 0, mask⟩ result mask how            -- 3311–3346

/-- `pg_namespace_aclmask_ext` (aclchk.c:3896–4030).
    The temp-schema path calls `object_aclcheck_ext` on the current database,
    which itself can reach the hook (3930–3937). -/
def pgNamespaceAclmask (e : Env) (nsp role : Oid) (mask : AclMode) (how : How) :
    AclMode × Option AuthInfo :=
  if e.superuser role then (mask, none)                                  -- 3908–3909
  else if e.cat.isTempNsp nsp then                                       -- 3930–3937
    let (r, call) := objectAclmaskBase e .database e.myDb role ACL_CREATE_TEMP .any
    if r != 0 then (mask &&& ACL_ALL_RIGHTS_SCHEMA, call)
    else (mask &&& ACL_USAGE, call)
  else if !e.cat.nspFound nsp then (0, none)                             -- 3942–3950
  else
    let result := e.aclmask ⟨.namespace, nsp, 0⟩ role mask how            -- 3973
    hookBlock e ⟨role, .namespace, nsp, 0, mask⟩ result mask how         -- 3992–4027

/-- `pg_type_aclmask_ext` (aclchk.c:4036–4192).
    Native ACL comes from the resolved element/range type, but the hook is
    told the original `type_oid` (4176–4177). -/
def pgTypeAclmask (e : Env) (typ role : Oid) (mask : AclMode) (how : How) :
    AclMode × Option AuthInfo :=
  if e.superuser role then (mask, none)                                  -- 4048–4049
  else match e.cat.typeAclOid typ with
    | none => (0, none)                                                  -- 4054–4126
    | some aclOid =>
      let result := e.aclmask ⟨.type, aclOid, 0⟩ role mask how            -- 4147
      hookBlock e ⟨role, .type, typ, 0, mask⟩ result mask how            -- 4155–4190

/-! ## Layer 3: dispatch -/

/-- `object_aclmask_ext` (aclchk.c:3231–3349): namespaces and types are
    forwarded (3244–3252). -/
def objectAclmask (e : Env) (classid : ClassId) (obj role : Oid)
    (mask : AclMode) (how : How) : AclMode × Option AuthInfo :=
  match classid with
  | .namespace => pgNamespaceAclmask e obj role mask how
  | .type      => pgTypeAclmask e obj role mask how
  | c          => objectAclmaskBase e c obj role mask how

/-! ## Theorems -/

/-- Superusers never cause a hook call on tables. -/
theorem pgClass_superuser_no_hook (e : Env) (t role : Oid) (m : AclMode) (h : How)
    (hs : e.superuser role = true) :
    (pgClassAclmask e t role m h).2 = none := by
  unfold pgClassAclmask
  split
  · rfl
  · simp [hs]

/-- If the mask has no catalog write bits, the hook block cannot add any
    (uses `hookBlock_sound` and the `WellFormed` assumption). -/
theorem hookBlock_no_new_write_bits (e : Env) (he : e.WellFormed) (k : AclKey) (role : Oid)
    (h : How) (m : AclMode) (info : AuthInfo) (hm : m &&& catalogWriteBits = 0) :
    (hookBlock e info (e.aclmask k role m h) m h).1 &&& catalogWriteBits = 0 := by
  have hs := hookBlock_sound e info (e.aclmask k role m h) m h
  have hw := he k role m h
  bv_decide

/-- The mask stripping at aclchk.c:3573–3577 leaves no catalog write bits. -/
theorem catalog_strip_clears (m : AclMode) :
    (if (m &&& catalogWriteBits != 0) = true then m &&& ~~~catalogWriteBits else m)
      &&& catalogWriteBits = 0 := by
  by_cases hc : (m &&& catalogWriteBits != 0) = true
  · simp only [hc, ite_true]
    bv_decide
  · simp only [hc, Bool.false_eq_true, ite_false]
    simp at hc
    exact hc

/-- **Catalog write protection**: whatever the hook returns, a non-superuser
    never gets INSERT/UPDATE/DELETE/TRUNCATE/USAGE on a system catalog that is
    not a view. -/
theorem pgClass_catalog_write_protected (e : Env) (he : e.WellFormed)
    (t role : Oid) (r : ClassRow) (hrow : e.cat.classRow t = some r)
    (hsys : r.isSystem = true) (hview : r.isView = false) (hsu : e.superuser role = false)
    (m : AclMode) (h : How) :
    (pgClassAclmask e t role m h).1 &&& catalogWriteBits = 0 := by
  unfold pgClassAclmask
  rw [hrow]
  simp only [hsys, hview, hsu, Bool.false_eq_true, ite_false, Bool.and_true, Bool.not_false]
  exact hookBlock_no_new_write_bits e he _ role h _ _ (catalog_strip_clears m)

/-- A column with no column-level ACL never reaches Cedar (finding: Cedar
    `Column` policies only matter for columns that already have a GRANT). -/
theorem pgAttribute_no_acl_never_asks (e : Env) (t : Oid) (a : Int) (row : AttRow)
    (hrow : e.cat.attRow t a = some row) (hnull : row.aclNull = true)
    (role : Oid) (m : AclMode) (h : How) :
    pgAttributeAclmask e t a role m h = (0, none) := by
  unfold pgAttributeAclmask
  rw [hrow]
  dsimp only
  split <;> simp_all

/-- The type hook is asked about the original OID, not the one whose ACL was used. -/
theorem pgType_hook_sees_original_oid (e : Env) (typ role : Oid) (m : AclMode) (h : How)
    (i : AuthInfo) (hc : (pgTypeAclmask e typ role m h).2 = some i) :
    i.objectid = typ := by
  unfold pgTypeAclmask at hc
  split at hc
  · simp at hc
  · split at hc
    · simp at hc
    · rw [hookBlock_info e _ i _ _ _ hc]

end Arcade.Aclchk
