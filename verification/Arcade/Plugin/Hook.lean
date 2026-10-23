import Arcade.Plugin.Response
import Arcade.Plugin.Cache

/-! # `cedar_authorization_hook` (pg_authorization.c:812–1115)

The hook is a state transformer: it reads and updates the shared cache and
sends zero or more requests to the Cedar agent. The model returns all three:
`(result, new cache state, requests sent)`.

Modelled: the chained previous hook, the three early exits, and the
`PG_AUTH_EVENT_ACL_CHECK` branch with its per-bit loop.

Not modelled: the DML and DDL/UTILITY branches. `build_eventType` proves the
core only ever sends ACL_CHECK, so they are unreachable from the patched core;
the model returns IGNORE for them.

The loop runs `for (i = 0; i < 32; i++)` with `AclMode bit = (1 << i)`. At
`i = 31` this shifts into the sign bit of an `int` (undefined behaviour). Bit
31 has no Cedar action, so it is skipped either way; the model uses the
intended `1 <<< 31`.
-/

namespace Arcade.Plugin
open Arcade.Aclchk

/-- `get_cedar_action_for_bit` (pg_authorization.c:363–395), by bit position. -/
def actionForBit : Nat → Option String
  | 0  => some "INSERT"     | 1  => some "SELECT"       | 2  => some "UPDATE"
  | 3  => some "DELETE"     | 4  => some "TRUNCATE"     | 5  => some "REFERENCES"
  | 6  => some "TRIGGER"    | 7  => some "EXECUTE"      | 8  => some "USAGE"
  | 9  => some "CREATE"     | 10 => some "CREATE_TEMP"  | 11 => some "CONNECT"
  | 12 => some "SET"        | 13 => some "ALTER_SYSTEM" | 14 => some "MAINTAIN"
  | _  => none

/-- `AclMode bit = (1 << i)` (980). -/
def bitOf (i : Nat) : AclMode := 1#64 <<< i

/-- Resource type for ACL_CHECK (pg_authorization.c:941–963). -/
def aclResourceType (c : ClassId) (subid : Int) : String :=
  match c with
  | .relation  => if subid ≠ 0 then "Column" else "Table"
  | .namespace => "Schema"
  | .type      => "Type"
  | .database  => "Database"
  | .procedure => "Routine"
  | .other     => "Object"

/-- The principal: `auth_info->rolename`, else a syscache lookup, else "unknown" (993–1007). -/
def principalOf (pe : PEnv) (info : AuthorizationInfo) : String :=
  match info.rolename with
  | some n => if n = "" then (pe.roleName info.roleid).getD "unknown" else n
  | none   => (pe.roleName info.roleid).getD "unknown"

/-- The request sent for one bit (1092–1099). -/
def reqFor (pe : PEnv) (info : AuthorizationInfo) (c : ClassId) (obj : Oid) (subid : Int)
    (ctx : Context) (action : String) : CedarReq :=
  ⟨principalOf pe info, action, aclResourceType c subid, pe.resourceId c obj subid, ctx⟩

/-- The per-bit loop (pg_authorization.c:979–1108). -/
def bitLoop (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat) (info : AuthorizationInfo)
    (c : ClassId) (obj : Oid) (subid : Int) (mask : AclMode) :
    List Nat → CacheState → List CedarReq → HookResult × CacheState × List CedarReq
  | [], st, sent => (.grant, st, sent)                                        -- 1108
  | i :: is, st, sent =>
    if mask &&& bitOf i = 0 then bitLoop pe agent ctx now info c obj subid mask is st sent   -- 981
    else
      -- key = ⟨info.roleid, c, obj, subid, i⟩; written out in full (no `let`) so proofs can split on it
      if (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).1 ≠ .ignore then        -- 983–984
        if (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).1 ≠ .grant then        -- 985–988
          ((checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).1,
           (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).2, sent)
        else bitLoop pe agent ctx now info c obj subid mask is
               (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).2 sent            -- 989
      else
        match actionForBit i with                                                          -- 1092–1093
        | none   => bitLoop pe agent ctx now info c obj subid mask is
                      (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).2 sent
        | some a =>
          -- r = mapHttp (agent (reqFor …)) (1095–1099); IGNORE is not cached (1099–1100)
          if mapHttp (agent (reqFor pe info c obj subid ctx a)) = .grant then
            bitLoop pe agent ctx now info c obj subid mask is
              (updateCache pe.cfg (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).2 now
                 ⟨info.roleid, c, obj, subid, i⟩ .grant)
              (sent ++ [reqFor pe info c obj subid ctx a])
          else
            (mapHttp (agent (reqFor pe info c obj subid ctx a)),                          -- 1101–1103
             (if mapHttp (agent (reqFor pe info c obj subid ctx a)) = .ignore
              then (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).2
              else updateCache pe.cfg (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).2 now
                     ⟨info.roleid, c, obj, subid, i⟩ (mapHttp (agent (reqFor pe info c obj subid ctx a)))),
             sent ++ [reqFor pe info c obj subid ctx a])

/-- The ACL_CHECK branch (pg_authorization.c:941–963, 973–976). -/
def aclCheckBranch (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) : HookResult × CacheState × List CedarReq :=
  match info.info.readDDL with
  | none   => (.ignore, st, [])
  | some d =>
    if d.requiredPerms = 0 then (.grant, st, [])                              -- 973–976
    else bitLoop pe agent ctx now info (d.classid.getD .other) d.objectid d.subid
           d.requiredPerms (List.range 32) st []

/-- The hook's own logic after the chained hook (pg_authorization.c:836–844). -/
def ownHook (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) : HookResult × CacheState × List CedarReq :=
  if !pe.cfg.enabled then (.ignore, st, [])                                   -- 836–837
  else if pe.superuser info.roleid then (.ignore, st, [])                     -- 840–841
  else if pe.cfg.agentUrl = "" then (.ignore, st, [])                         -- 843–844
  else match info.eventType with
    | .aclCheck => aclCheckBranch pe agent ctx now info st
    | _         => (.ignore, st, [])                                          -- not modelled

/-- `cedar_authorization_hook`. The previous hook in the chain runs first (830–834). -/
def cedarHook (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) : HookResult × CacheState × List CedarReq :=
  match pe.prevHook with
  | some p => if p info ≠ .ignore then (p info, st, []) else ownHook pe agent ctx now info st
  | none   => ownHook pe agent ctx now info st

/-! ## Guards -/

theorem cedarHook_disabled (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) (hp : pe.prevHook = none)
    (h : pe.cfg.enabled = false) :
    cedarHook pe agent ctx now info st = (.ignore, st, []) := by
  simp [cedarHook, hp, ownHook, h]

theorem cedarHook_superuser (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) (hp : pe.prevHook = none)
    (h : pe.superuser info.roleid = true) :
    cedarHook pe agent ctx now info st = (.ignore, st, []) := by
  simp [cedarHook, hp, ownHook, h]

theorem cedarHook_no_url (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) (hp : pe.prevHook = none)
    (h : pe.cfg.agentUrl = "") :
    cedarHook pe agent ctx now info st = (.ignore, st, []) := by
  simp [cedarHook, hp, ownHook, h]

/-- A previous hook in the chain decides first: if it returns anything but
    IGNORE, Cedar is never consulted. -/
theorem cedarHook_prev_wins (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) (p : AuthorizationInfo → HookResult)
    (hp : pe.prevHook = some p) (hr : p info ≠ .ignore) :
    cedarHook pe agent ctx now info st = (p info, st, []) := by
  simp [cedarHook, hp, hr]

/-! ## The loop -/

/-- The cache entries a loop for `info` relies on agree with Cedar. -/
def expectedFor (pe : PEnv) (agent : Agent) (ctx : Context) (info : AuthorizationInfo)
    (k : CacheKey) : HookResult :=
  match actionForBit k.action with
  | some a => mapHttp (agent (reqFor pe info k.classid k.obj k.subid ctx a))
  | none   => .ignore

/-- **Loop soundness**: with a cache that agrees with Cedar, the loop returns
    GRANT only if Cedar allows every requested bit that has a Cedar action. -/
theorem bitLoop_grant (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (c : ClassId) (obj : Oid) (subid : Int) (mask : AclMode) :
    ∀ (is : List Nat) (st : CacheState) (sent : List CedarReq),
      CacheSound st now (expectedFor pe agent ctx info) →
      (bitLoop pe agent ctx now info c obj subid mask is st sent).1 = .grant →
      ∀ i ∈ is, mask &&& bitOf i ≠ 0 → ∀ a, actionForBit i = some a →
        mapHttp (agent (reqFor pe info c obj subid ctx a)) = .grant := by
  intro is
  induction is with
  | nil => intro _ _ _ _ i hi; cases hi
  | cons j js ih =>
    intro st sent hs hg i hi hbit a ha
    have ⟨hc1, hc2⟩ := checkCache_sound pe.cfg st now ⟨info.roleid, c, obj, subid, j⟩ _ hs
    -- what the recursive call gives us, for any sound state
    have hrec : ∀ st', CacheSound st' now (expectedFor pe agent ctx info) → ∀ sent',
        (bitLoop pe agent ctx now info c obj subid mask js st' sent').1 = .grant →
        i ∈ js → mapHttp (agent (reqFor pe info c obj subid ctx a)) = .grant :=
      fun st' h1 sent' h2 hm => ih st' sent' h1 h2 i hm hbit a ha
    unfold bitLoop at hg
    split at hg
    · -- bit j not requested: skipped
      rename_i hz
      rcases List.mem_cons.mp hi with rfl | hmem
      · exact absurd hz hbit
      · exact hrec st hs sent hg hmem
    · split at hg
      · -- cache hit
        rename_i hne
        split at hg
        · exact absurd hg ‹_›
        · rename_i hgr
          rcases List.mem_cons.mp hi with rfl | hmem
          · rcases hc1 with h0 | h1
            · exact absurd h0 hne
            · have hgr' : (checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩).1 = .grant :=
                Decidable.of_not_not hgr
              rw [h1] at hgr'
              simpa [expectedFor, ha] using hgr'
          · exact hrec _ hc2 sent hg hmem
      · -- cache miss
        rename_i hmiss
        split at hg
        · rename_i hnone
          rcases List.mem_cons.mp hi with rfl | hmem
          · rw [ha] at hnone; cases hnone
          · exact hrec _ hc2 sent hg hmem
        · rename_i a' ha'
          split at hg
          · rename_i hgr
            rcases List.mem_cons.mp hi with rfl | hmem
            · rw [ha] at ha'; cases ha'; exact hgr
            · apply hrec _ _ _ hg hmem
              have hu := updateCache_sound pe.cfg _ now ⟨info.roleid, c, obj, subid, j⟩ _ hc2
              simpa [expectedFor, ha', hgr] using hu
          · simp at hg; exact absurd hg ‹_›

/-- If no requested bit is in the range the loop scans, the loop does nothing
    and returns GRANT. -/
theorem bitLoop_skip (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (c : ClassId) (obj : Oid) (subid : Int) (mask : AclMode) :
    ∀ (is : List Nat) (st : CacheState) (sent : List CedarReq),
      (∀ i ∈ is, mask &&& bitOf i = 0) →
      bitLoop pe agent ctx now info c obj subid mask is st sent = (.grant, st, sent) := by
  intro is
  induction is with
  | nil => intro _ _ _; rfl
  | cons j js ih =>
    intro st sent h
    unfold bitLoop
    simp only [h j (by simp), ↓reduceIte]
    exact ih st sent (fun i hi => h i (by simp [hi]))

/-- Every ACL bit that PostgreSQL 17 defines (positions 0–14) has a Cedar action. -/
theorem actionForBit_defined : ∀ i, i < 15 → (actionForBit i).isSome = true := by decide

/-- **Hook soundness** (ACL_CHECK, no chained hook, cache agreeing with Cedar):
    GRANT means Cedar allowed every requested bit that has a Cedar action. -/
theorem cedarHook_grant (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) (d : DDLInfo)
    (hp : pe.prevHook = none) (hev : info.eventType = .aclCheck) (hd : info.info.readDDL = some d)
    (hs : CacheSound st now (expectedFor pe agent ctx info))
    (hg : (cedarHook pe agent ctx now info st).1 = .grant) :
    ∀ i < 32, d.requiredPerms &&& bitOf i ≠ 0 → ∀ a, actionForBit i = some a →
      mapHttp (agent (reqFor pe info (d.classid.getD .other) d.objectid d.subid ctx a)) = .grant := by
  intro i hi hbit a ha
  simp only [cedarHook, hp, ownHook, hev] at hg
  split at hg
  · simp at hg
  · split at hg
    · simp at hg
    · split at hg
      · simp at hg
      · simp only [aclCheckBranch, hd] at hg
        split at hg
        · rename_i hz; rw [hz] at hbit; simp at hbit
        · exact bitLoop_grant pe agent ctx now info _ _ _ _ _ st [] hs hg i
            (List.mem_range.mpr hi) hbit a ha

/-- **Cedar unreachable**: with every request failing and no usable cached
    answer, GRANT is only possible if no defined privilege bit (0–14) was
    requested. -/
theorem cedarHook_agent_down (pe : PEnv) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) (d : DDLInfo)
    (hp : pe.prevHook = none) (hev : info.eventType = .aclCheck) (hd : info.info.readDDL = some d)
    (hs : CacheSound st now (expectedFor pe (fun _ => .curlError) ctx info))
    (hg : (cedarHook pe (fun _ => .curlError) ctx now info st).1 = .grant) :
    ∀ i < 15, d.requiredPerms &&& bitOf i = 0 := by
  intro i hi
  apply Classical.byContradiction
  intro hbit
  obtain ⟨a, ha⟩ := Option.isSome_iff_exists.mp (actionForBit_defined i hi)
  have := cedarHook_grant pe _ ctx now info st d hp hev hd hs hg i (by omega) hbit a ha
  simp [mapHttp] at this

/-- **Finding (grant options)**: if the requested mask has no bits in positions
    0–31, the loop never looks at it and the hook returns GRANT without asking
    Cedar. Grant-option bits live in positions 32–63 (`ACL_GRANT_OPTION_FOR`,
    acl.h:70), so e.g. `has_table_privilege(…, 'SELECT WITH GRANT OPTION')`
    reaches the hook with only bit 33 set. -/
theorem cedarHook_high_bits_granted (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (st : CacheState) (d : DDLInfo)
    (hp : pe.prevHook = none) (hen : pe.cfg.enabled = true) (hsu : pe.superuser info.roleid = false)
    (hurl : pe.cfg.agentUrl ≠ "")
    (hev : info.eventType = .aclCheck) (hd : info.info.readDDL = some d)
    (hlow : ∀ i, i < 32 → d.requiredPerms &&& bitOf i = 0) :
    cedarHook pe agent ctx now info st = (.grant, st, []) := by
  simp only [cedarHook, hp, ownHook, hen, hsu, hurl, hev, aclCheckBranch, hd]
  simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
  split
  · rfl
  · exact bitLoop_skip pe agent ctx now info _ _ _ _ _ st []
      (fun i hi => hlow i (List.mem_range.mp hi))

/-- `ACL_GRANT_OPTION_FOR(ACL_SELECT)` (acl.h:70) has only bit 33 set. -/
def grantOptionSelect : AclMode := ACL_SELECT <<< 32

theorem grantOptionSelect_low_clear : ∀ i, i < 32 → grantOptionSelect &&& bitOf i = 0 := by
  decide

end Arcade.Plugin
