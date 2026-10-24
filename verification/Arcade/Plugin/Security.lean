import Arcade.Plugin.System

/-! # The whole-system security property

The paper's claim (§3.2): ARCADE only adds privileges that Cedar grants.
`Secure` states it for the patched core with a hook installed: whenever the
hook block changes the outcome of a privilege check, Cedar allows every
privilege bit the check asked for.

* `original_not_secure`: pg_authorization as written violates it for every
  policy (grant-option bits, finding F1).
* `allow_reason_not_secure`: it also violates it for an honest agent whose
  Deny names a policy `Allow` (finding F3).
* `fixed_secure`: a fixed plugin satisfies it, given a cache that agrees with
  the current policies (findings F4 and F5 are the ways the real cache does not).

"What Cedar decides" is modelled as `Policy`: Cedar's answer to each request
under the current policies and entities. The agent prints it as JSON
(`CedarAnswer.render`, the format of the mock agent), or the request fails.
-/

namespace Arcade.Plugin
open Arcade.Aclchk

/-! ## What Cedar decides -/

/-- Cedar's answer as the agent computes it, before printing it. -/
structure CedarAnswer where
  allow   : Bool
  reasons : List String    -- diagnostics.reason: ids of the deciding policies
  deriving DecidableEq, Repr

/-- The agent's JSON response body. -/
def CedarAnswer.render (r : CedarAnswer) : String :=
  "{\"decision\":\"" ++ (if r.allow then "Allow" else "Deny") ++
  "\",\"diagnostics\":{\"reason\":[" ++
  ",".intercalate (r.reasons.map fun s => "\"" ++ s ++ "\"") ++ "],\"errors\":[]}}"

/-- Cedar's decision for every request, under the current policies. -/
abbrev Policy := CedarReq → CedarAnswer

/-- The agent prints Cedar's answer, or the request fails (transport error or
    a non-200 status). This covers an honest agent and any outage pattern. -/
def Faithful (pol : Policy) (agent : Agent) : Prop :=
  ∀ q, agent q = .response 200 (pol q).render ∨ agent q = .curlError ∨
    ∃ code body, code ≠ 200 ∧ agent q = .response code body

/-- An agent that is always reachable and honest. -/
def honest (pol : Policy) : Agent := fun q => .response 200 (pol q).render

theorem honest_faithful (pol : Policy) : Faithful pol (honest pol) := fun _ => .inl rfl

/-- Cedar allows bit `i` of a check: the bit has a Cedar action, and Cedar's
    answer for that action is Allow. A bit with no Cedar action is never allowed. -/
def CedarAllows (pol : Policy) (pe : PEnv) (info : AuthorizationInfo) (c : ClassId) (obj : Oid)
    (subid : Int) (ctx : Context) (i : Nat) : Prop :=
  ∃ a, actionForBit i = some a ∧ (pol (reqFor pe info c obj subid ctx a)).allow = true

/-! ## The property -/

/-- **Security**: for every check the core makes (any of the five hook sites,
    any native result), if the hook block changes the result then Cedar allows
    every requested bit. With `hookBlock_additive` and `hookBlock_sound` this
    pins the outcome down: native result, or native ∪ mask with Cedar's approval. -/
def Secure (e : Env) (pol : Policy) (pe : PEnv) (ctx : Context) : Prop :=
  ∀ (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m result : AclMode) (how : How),
    (hookBlock e ⟨role, c, obj, s, m⟩ result m how).1 ≠ result →
    ∀ i < 64, m &&& bitOf i ≠ 0 →
      CedarAllows pol pe (buildHookInfo e role c obj s m) c obj s ctx i

/-- `Secure` at a real call site: on a user table, if `pg_class_aclmask`
    returns something other than the native answer, Cedar allowed every
    requested bit. -/
theorem Secure.pgClass {E : Env} {pol : Policy} {pe : PEnv} {ctx : Context}
    (hS : Secure E pol pe ctx) (t role : Oid) (r : ClassRow) (hrow : E.cat.classRow t = some r)
    (hsys : r.isSystem = false) (hsu : E.superuser role = false) (m : AclMode) (how : How)
    (hne : (pgClassAclmask E t role m how).1 ≠ E.aclmask ⟨.relation, t, 0⟩ role m how) :
    ∀ i < 64, m &&& bitOf i ≠ 0 →
      CedarAllows pol pe (buildHookInfo E role .relation t 0 m) .relation t 0 ctx i := by
  simp only [pgClassAclmask, hrow, hsys, hsu, Bool.and_false, Bool.false_and,
    Bool.false_eq_true, ↓reduceIte] at hne
  exact hS role .relation t 0 m _ how hne

/-! ## The plugin as written is not secure -/

/-- **F1 as a security violation**: whatever Cedar's policies are and whatever
    the agent does, the grant-option check on table 0 changes from denied to
    granted, yet bit 33 has no Cedar action. -/
theorem original_not_secure (e : Env) (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (st : CacheState) (pol : Policy)
    (hp : pe.prevHook = none) (hen : pe.cfg.enabled = true) (hurl : pe.cfg.agentUrl ≠ "")
    (role : Oid) (hpsu : pe.superuser role = false) :
    ¬ Secure (withCedar e pe agent ctx now st) pol pe ctx := by
  intro hS
  have hc := cedarHook_high_bits_granted pe agent ctx now
    (AuthInfo.toFull e ⟨role, .relation, 0, 0, grantOptionSelect⟩) st _ hp hen hpsu hurl rfl
    (build_readDDL e role .relation 0 0 grantOptionSelect) grantOptionSelect_low_clear
  have hne : (hookBlock (withCedar e pe agent ctx now st) ⟨role, .relation, 0, 0, grantOptionSelect⟩
      0 grantOptionSelect .any).1 ≠ 0 := by
    have h0 : (0 &&& grantOptionSelect != 0) = false := by decide
    simp only [hookBlock, withCedar, sufficient, hc, h0, Bool.false_eq_true, ↓reduceIte]
    decide
  obtain ⟨a, ha, _⟩ := hS role .relation 0 0 grantOptionSelect 0 .any hne 33 (by omega) (by decide)
  simp [actionForBit] at ha

/-- With every request answered GRANT and a cache that only ever serves GRANT,
    the loop returns GRANT. -/
theorem bitLoop_allow_all (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (info : AuthorizationInfo) (c : ClassId) (obj : Oid) (subid : Int) (mask : AclMode)
    (hall : ∀ q, mapHttp (agent q) = .grant) :
    ∀ (is : List Nat) (st : CacheState) (sent : List CedarReq),
      CacheSound st now (fun _ => .grant) →
      (bitLoop pe agent ctx now info c obj subid mask is st sent).1 = .grant := by
  intro is
  induction is with
  | nil => intro _ _ _; rfl
  | cons j js ih =>
    intro st sent hs
    have ⟨hc1, hc2⟩ := checkCache_sound pe.cfg st now ⟨info.roleid, c, obj, subid, j⟩ _ hs
    unfold bitLoop
    split
    · exact ih st sent hs
    · split
      · rename_i hni
        split
        · rename_i hng
          rcases hc1 with h | h
          · exact absurd h hni
          · exact absurd h hng
        · exact ih _ sent hc2
      · split
        · exact ih _ sent hc2
        · simp only [hall, ↓reduceIte]
          exact ih _ _ (updateCache_sound pe.cfg _ now _ (fun _ => .grant) hc2)

/-- A Deny whose diagnostics name a policy `Allow`. -/
def denyAllowReason : Policy := fun _ => ⟨false, ["Allow"]⟩

theorem mapHttp_denyAllowReason (q : CedarReq) :
    mapHttp (honest denyAllowReason q) = .grant := by
  show mapHttp (.response 200 (CedarAnswer.render ⟨false, ["Allow"]⟩)) = .grant
  decide

/-- **F3 as a security violation**: an honest, reachable agent denies every
    request, but its responses name a policy `Allow`; with a fresh cache, a
    table SELECT check changes from denied to granted. -/
theorem allow_reason_not_secure (e : Env) (pe : PEnv) (ctx : Context) (now : Nat) (st : CacheState)
    (hp : pe.prevHook = none) (hen : pe.cfg.enabled = true) (hurl : pe.cfg.agentUrl ≠ "")
    (role : Oid) (hpsu : pe.superuser role = false) (hfresh : NoServable st now) :
    ¬ Secure (withCedar e pe (honest denyAllowReason) ctx now st) denyAllowReason pe ctx := by
  intro hS
  have hg : (cedarHook pe (honest denyAllowReason) ctx now
      (AuthInfo.toFull e ⟨role, .relation, 0, 0, ACL_SELECT⟩) st).1 = .grant := by
    simp only [cedarHook, hp, ownHook, AuthInfo.toFull, buildHookInfo, initAuthorizationInfo,
      hen, hpsu, hurl, aclCheckBranch, InfoUnion.writeDDL, InfoUnion.readDDL, Option.getD,
      Bool.not_true, Bool.false_eq_true, ↓reduceIte]
    split
    · rfl
    · exact bitLoop_allow_all pe _ ctx now _ _ _ _ _ mapHttp_denyAllowReason _ st []
        (cacheSound_of_noServable st now hfresh _)
  have hne : (hookBlock (withCedar e pe (honest denyAllowReason) ctx now st)
      ⟨role, .relation, 0, 0, ACL_SELECT⟩ 0 ACL_SELECT .all).1 ≠ 0 := by
    have h0 : (0 &&& ACL_SELECT == ACL_SELECT) = false := by decide
    simp only [hookBlock, withCedar, sufficient, hg, h0, Bool.false_eq_true, ↓reduceIte]
    decide
  obtain ⟨a, ha, hal⟩ := hS role .relation 0 0 ACL_SELECT 0 .all hne 1 (by omega) (by decide)
  simp [denyAllowReason] at hal

/-! ## A fixed plugin -/

/-- Fix for F3: read the `decision` field with a JSON parser instead of
    searching the body. The parser is a parameter; `ParserCorrect` is what we
    assume about it. -/
def mapHttpFixed (parse : String → Option Bool) : HttpOutcome → HookResult
  | .curlError => .ignore
  | .response code body =>
    if code = 200 then
      match parse body with
      | some true  => .grant
      | some false => .deny
      | none       => .ignore
    else .ignore

/-- Assumption: the parser reads the decision out of every response the agent prints. -/
def ParserCorrect (parse : String → Option Bool) : Prop :=
  ∀ r : CedarAnswer, parse r.render = some r.allow

def decisionPrefix : String := "{\"decision\":\""

/-- A parser that satisfies the assumption, so `fixed_secure` is not vacuous:
    it checks that the body starts with `{"decision":"Allow` or `{"decision":"Deny`.
    A JSON library would also accept reordered fields. -/
def parseDecision (s : String) : Option Bool :=
  if (decisionPrefix ++ "Allow").toList.isPrefixOf s.toList then some true
  else if (decisionPrefix ++ "Deny").toList.isPrefixOf s.toList then some false
  else none

theorem parseDecision_correct : ParserCorrect parseDecision := by
  intro ⟨allow, reasons⟩
  cases allow <;>
  simp [parseDecision, CedarAnswer.render, decisionPrefix, String.toList_append,
    List.isPrefixOf_iff_prefix]

/-- The fixed parser rejects the response that fooled the original (F3). -/
theorem parseDecision_denyAllowReason (q : CedarReq) :
    mapHttpFixed parseDecision (honest denyAllowReason q) = .deny :=
  by simp only [honest, mapHttpFixed, ↓reduceIte]; rw [parseDecision_correct]; rfl

/-- GRANT or DENY, according to Cedar's answer. -/
def truth (r : CedarAnswer) : HookResult := if r.allow then .grant else .deny

/-- From a faithful agent, the fixed mapping gives Cedar's answer or IGNORE. -/
theorem mapHttpFixed_faithful (parse : String → Option Bool) (pol : Policy) (agent : Agent)
    (hpc : ParserCorrect parse) (hf : Faithful pol agent) (q : CedarReq) :
    mapHttpFixed parse (agent q) = .ignore ∨ mapHttpFixed parse (agent q) = truth (pol q) := by
  rcases hf q with h | h | ⟨code, body, hc, h⟩ <;> rw [h]
  · right
    simp only [mapHttpFixed, ↓reduceIte]
    rw [hpc]
    unfold truth
    cases (pol q).allow <;> rfl
  · left; rfl
  · left; simp [mapHttpFixed, hc]

/-- The per-bit loop with both fixes: it scans all 64 bits (the caller passes
    `List.range 64`), and a requested bit with no Cedar action is denied
    (fix for F1). -/
def bitLoopFixed (parse : String → Option Bool) (pe : PEnv) (agent : Agent) (ctx : Context)
    (now : Nat) (info : AuthorizationInfo) (c : ClassId) (obj : Oid) (subid : Int)
    (mask : AclMode) : List Nat → CacheState → HookResult × CacheState
  | [], st => (.grant, st)
  | i :: is, st =>
    if mask &&& bitOf i = 0 then bitLoopFixed parse pe agent ctx now info c obj subid mask is st
    else match actionForBit i with
      | none   => (.deny, st)
      | some a =>
        match checkCache pe.cfg st now ⟨info.roleid, c, obj, subid, i⟩ with
        | (.grant, st')  => bitLoopFixed parse pe agent ctx now info c obj subid mask is st'
        | (.deny, st')   => (.deny, st')
        | (.ignore, st') =>
          match mapHttpFixed parse (agent (reqFor pe info c obj subid ctx a)) with
          | .grant  => bitLoopFixed parse pe agent ctx now info c obj subid mask is
                         (updateCache pe.cfg st' now ⟨info.roleid, c, obj, subid, i⟩ .grant)
          | .deny   => (.deny, updateCache pe.cfg st' now ⟨info.roleid, c, obj, subid, i⟩ .deny)
          | .ignore => (.ignore, st')

/-- `ownHook` with the fixed loop. -/
def ownHookFixed (parse : String → Option Bool) (pe : PEnv) (agent : Agent) (ctx : Context)
    (now : Nat) (info : AuthorizationInfo) (st : CacheState) : HookResult × CacheState :=
  if !pe.cfg.enabled then (.ignore, st)
  else if pe.superuser info.roleid then (.ignore, st)
  else if pe.cfg.agentUrl = "" then (.ignore, st)
  else if info.eventType ≠ .aclCheck then (.ignore, st)
  else match info.info.readDDL with
    | none   => (.ignore, st)
    | some d =>
      if d.requiredPerms = 0 then (.grant, st)
      else bitLoopFixed parse pe agent ctx now info (d.classid.getD .other) d.objectid d.subid
             d.requiredPerms (List.range 64) st

def cedarHookFixed (parse : String → Option Bool) (pe : PEnv) (agent : Agent) (ctx : Context)
    (now : Nat) (info : AuthorizationInfo) (st : CacheState) : HookResult × CacheState :=
  match pe.prevHook with
  | some p => if p info ≠ .ignore then (p info, st) else ownHookFixed parse pe agent ctx now info st
  | none   => ownHookFixed parse pe agent ctx now info st

def withCedarFixed (e : Env) (parse : String → Option Bool) (pe : PEnv) (agent : Agent)
    (ctx : Context) (now : Nat) (st : CacheState) : Env :=
  { e with hook := some (fun ai => (cedarHookFixed parse pe agent ctx now (ai.toFull e) st).1) }

/-- Cedar's answer for a cache key, under the current policies and context. -/
def truthKey (e : Env) (pe : PEnv) (pol : Policy) (ctx : Context) (k : CacheKey) : HookResult :=
  match actionForBit k.action with
  | some a => truth (pol (reqFor pe (buildHookInfo e k.role k.classid k.obj k.subid 0)
                k.classid k.obj k.subid ctx a))
  | none   => .ignore

/-- **Fixed loop soundness**: with a cache that agrees with Cedar, GRANT means
    Cedar allows every requested bit in the scanned range. -/
theorem bitLoopFixed_grant (parse : String → Option Bool) (pol : Policy) (pe : PEnv)
    (agent : Agent) (ctx : Context) (now : Nat) (info : AuthorizationInfo) (c : ClassId)
    (obj : Oid) (subid : Int) (mask : AclMode) (T : CacheKey → HookResult)
    (hpc : ParserCorrect parse) (hf : Faithful pol agent)
    (hT : ∀ i a, actionForBit i = some a →
      T ⟨info.roleid, c, obj, subid, i⟩ = truth (pol (reqFor pe info c obj subid ctx a))) :
    ∀ (is : List Nat) (st : CacheState), CacheSound st now T →
      (bitLoopFixed parse pe agent ctx now info c obj subid mask is st).1 = .grant →
      ∀ i ∈ is, mask &&& bitOf i ≠ 0 → CedarAllows pol pe info c obj subid ctx i := by
  intro is
  induction is with
  | nil => intro _ _ _ i hi; cases hi
  | cons j js ih =>
    intro st hs hg i hi hbit
    unfold bitLoopFixed at hg
    split at hg
    · rename_i hz
      rcases List.mem_cons.mp hi with rfl | hm
      · exact absurd hz hbit
      · exact ih st hs hg i hm hbit
    · split at hg
      · simp at hg
      · rename_i a ha
        have ⟨hc1, hc2⟩ := checkCache_sound pe.cfg st now ⟨info.roleid, c, obj, subid, j⟩ T hs
        split at hg
        · -- cache hit: GRANT
          rename_i st' heq
          rw [heq] at hc1 hc2
          rcases List.mem_cons.mp hi with rfl | hm
          · simp only [reduceCtorEq, false_or] at hc1
            rw [hT _ _ ha, truth] at hc1
            refine ⟨a, ha, ?_⟩
            split at hc1
            · assumption
            · cases hc1
          · exact ih st' hc2 hg i hm hbit
        · simp at hg
        · -- cache miss: ask the agent
          rename_i st' heq
          rw [heq] at hc2
          split at hg
          · rename_i hgr
            have htr : truth (pol (reqFor pe info c obj subid ctx a)) = .grant := by
              have := mapHttpFixed_faithful parse pol agent hpc hf (reqFor pe info c obj subid ctx a)
              rw [hgr] at this
              rcases this with h | h
              · cases h
              · exact h.symm
            rcases List.mem_cons.mp hi with rfl | hm
            · refine ⟨a, ha, ?_⟩
              rw [truth] at htr
              split at htr
              · assumption
              · cases htr
            · apply ih _ _ hg i hm hbit
              have := updateCache_sound pe.cfg st' now ⟨info.roleid, c, obj, subid, j⟩ T hc2
              rwa [hT _ _ ha, htr] at this
          · simp at hg
          · simp at hg

/-- **The fixed plugin is secure**, for any faithful agent (honest, down, or
    failing on some requests), provided the parser is correct and the cache
    agrees with the current policies in the current context. -/
theorem fixed_secure (e : Env) (parse : String → Option Bool) (pe : PEnv) (pol : Policy)
    (agent : Agent) (ctx : Context) (now : Nat) (st : CacheState)
    (hp : pe.prevHook = none) (hpc : ParserCorrect parse) (hf : Faithful pol agent)
    (hs : CacheSound st now (truthKey e pe pol ctx)) :
    Secure (withCedarFixed e parse pe agent ctx now st) pol pe ctx := by
  intro role c obj s m result how hne i hi hbit
  simp only [hookBlock, withCedarFixed] at hne
  split at hne
  · exact absurd rfl hne
  · split at hne
    · rename_i hg
      simp only [cedarHookFixed, hp, ownHookFixed, toFull_build, build_readDDL, build_eventType,
        ne_eq, not_true_eq_false, ↓reduceIte] at hg
      by_cases h1 : pe.cfg.enabled = true
      · by_cases h2 : pe.superuser role = true
        · simp [buildHookInfo, initAuthorizationInfo, h1, h2] at hg
        · by_cases h3 : pe.cfg.agentUrl = ""
          · simp [h1, h3] at hg
          · simp only [buildHookInfo, initAuthorizationInfo, h1, h2, h3, Bool.not_true,
              Bool.false_eq_true, ↓reduceIte, Option.getD] at hg
            by_cases hz : m = 0
            · rw [hz] at hbit; simp at hbit
            · simp only [hz, ↓reduceIte] at hg
              exact bitLoopFixed_grant parse pol pe agent ctx now (buildHookInfo e role c obj s m)
                c obj s m (truthKey e pe pol ctx) hpc hf
                (fun i a ha => by simp only [truthKey, ha]; rfl)
                (List.range 64) st hs hg i (List.mem_range.mpr hi) hbit
      · simp [h1] at hg
    · exact absurd rfl hne

/-- The concrete instance: the fixed plugin with `parseDecision` and a fresh
    cache (empty, or just reset) is secure for any faithful agent. -/
theorem fixed_secure_fresh (e : Env) (pe : PEnv) (pol : Policy) (agent : Agent) (ctx : Context)
    (now : Nat) (st : CacheState) (hp : pe.prevHook = none) (hf : Faithful pol agent)
    (hfresh : NoServable st now) :
    Secure (withCedarFixed e parseDecision pe agent ctx now st) pol pe ctx :=
  fixed_secure e parseDecision pe pol agent ctx now st hp parseDecision_correct hf
    (cacheSound_of_noServable st now hfresh _)

/-! ## The fix still grants

`Secure` alone is met by a hook that never grants. These theorems show the
fixed plugin grants whenever Cedar allows everything requested. -/

/-- **Fixed loop completeness**: with an honest agent and a cache that agrees
    with Cedar, if Cedar allows every requested bit, the loop returns GRANT. -/
theorem bitLoopFixed_complete (parse : String → Option Bool) (pol : Policy) (pe : PEnv)
    (ctx : Context) (now : Nat) (info : AuthorizationInfo) (c : ClassId)
    (obj : Oid) (subid : Int) (mask : AclMode) (T : CacheKey → HookResult)
    (hpc : ParserCorrect parse)
    (hT : ∀ i a, actionForBit i = some a →
      T ⟨info.roleid, c, obj, subid, i⟩ = truth (pol (reqFor pe info c obj subid ctx a))) :
    ∀ (is : List Nat) (st : CacheState), CacheSound st now T →
      (∀ i ∈ is, mask &&& bitOf i ≠ 0 → CedarAllows pol pe info c obj subid ctx i) →
      (bitLoopFixed parse pe (honest pol) ctx now info c obj subid mask is st).1 = .grant := by
  intro is
  induction is with
  | nil => intro _ _ _; rfl
  | cons j js ih =>
    intro st hs hall
    have hrest : ∀ i ∈ js, mask &&& bitOf i ≠ 0 → CedarAllows pol pe info c obj subid ctx i :=
      fun i hi => hall i (List.mem_cons_of_mem j hi)
    unfold bitLoopFixed
    split
    · exact ih st hs hrest
    · rename_i hbit
      obtain ⟨a, ha, hal⟩ := hall j (List.mem_cons_self ..) hbit
      have htr : truth (pol (reqFor pe info c obj subid ctx a)) = .grant := by simp [truth, hal]
      have ⟨hc1, hc2⟩ := checkCache_sound pe.cfg st now ⟨info.roleid, c, obj, subid, j⟩ T hs
      rw [hT _ _ ha, htr] at hc1
      simp only [ha]
      split
      · rename_i st' heq
        rw [heq] at hc2
        exact ih st' hc2 hrest
      · rename_i st' heq
        rw [heq] at hc1
        simp at hc1
      · rename_i st' heq
        rw [heq] at hc2
        have hmap : mapHttpFixed parse (honest pol (reqFor pe info c obj subid ctx a)) = .grant := by
          rcases mapHttpFixed_faithful parse pol _ hpc (honest_faithful pol)
            (reqFor pe info c obj subid ctx a) with h | h
          · simp only [honest, mapHttpFixed, ↓reduceIte] at h
            rw [hpc, hal] at h
            cases h
          · rw [h, htr]
        simp only [hmap]
        apply ih _ _ hrest
        have := updateCache_sound pe.cfg st' now ⟨info.roleid, c, obj, subid, j⟩ T hc2
        rwa [hT _ _ ha, htr] at this

/-- **The fixed plugin is complete**: with an honest agent and a cache that
    agrees with Cedar, a non-superuser's check (any site) passes whenever
    Cedar allows every requested bit. -/
theorem fixed_complete (e : Env) (parse : String → Option Bool) (pe : PEnv) (pol : Policy)
    (ctx : Context) (now : Nat) (st : CacheState)
    (hp : pe.prevHook = none) (hen : pe.cfg.enabled = true) (hurl : pe.cfg.agentUrl ≠ "")
    (hpc : ParserCorrect parse) (hs : CacheSound st now (truthKey e pe pol ctx))
    (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m result : AclMode) (how : How)
    (hsu : pe.superuser role = false) (hm : m ≠ 0)
    (hall : ∀ i < 64, m &&& bitOf i ≠ 0 →
      CedarAllows pol pe (buildHookInfo e role c obj s m) c obj s ctx i) :
    sufficient (hookBlock (withCedarFixed e parse pe (honest pol) ctx now st)
      ⟨role, c, obj, s, m⟩ result m how).1 m how = true := by
  have hg : (cedarHookFixed parse pe (honest pol) ctx now
      (AuthInfo.toFull e ⟨role, c, obj, s, m⟩) st).1 = .grant := by
    simp only [cedarHookFixed, hp, ownHookFixed, toFull_build, build_readDDL, build_eventType,
      ne_eq, not_true_eq_false, ↓reduceIte]
    simp only [buildHookInfo, initAuthorizationInfo, hen, hsu, hurl, hm, Bool.not_true,
      Bool.false_eq_true, ↓reduceIte, Option.getD]
    exact bitLoopFixed_complete parse pol pe ctx now (buildHookInfo e role c obj s m) c obj s m
      (truthKey e pe pol ctx) hpc (fun i a ha => by simp only [truthKey, ha]; rfl)
      (List.range 64) st hs (fun i hi => hall i (List.mem_range.mp hi))
  simp only [hookBlock, withCedarFixed]
  split
  · assumption
  · have hor : (result ||| m) &&& m = m := by
      apply BitVec.eq_of_getLsbD_eq; intro i; simp only [BitVec.getLsbD_and, BitVec.getLsbD_or]
      cases BitVec.getLsbD m i <;> simp
    cases how <;> simp [sufficient, hor] <;> exact hm

end Arcade.Plugin
