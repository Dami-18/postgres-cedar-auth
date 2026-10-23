import Arcade.Aclchk.Functions
import Arcade.Plugin.Hook

/-! # The patched core with pg_authorization installed

Plugs `cedarHook` into the aclchk.c model's `Env.hook`, for one privilege check
at time `now` against the cache snapshot `st`. The hook receives the full
`AuthorizationInfo` the core builds (`AuthInfo.toFull`, see AuthorizationHook.lean).
-/

namespace Arcade.Plugin
open Arcade.Aclchk

def withCedar (e : Env) (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (st : CacheState) : Env :=
  { e with hook := some (fun ai => (cedarHook pe agent ctx now (ai.toFull e) st).1) }

/-- No entry in the cache would be served at `now` (empty, or everything reset). -/
def NoServable (st : CacheState) (now : Nat) : Prop :=
  ∀ k e, (k, e) ∈ st.entries → isValid st now e = false

theorem cacheSound_of_noServable (st : CacheState) (now : Nat) (h : NoServable st now)
    (expected : CacheKey → HookResult) : CacheSound st now expected := by
  intro k e hm hv
  rw [h k e hm] at hv
  cases hv

/-- **End to end** (any of the five hook sites): the result is the native result,
    or native ∪ mask, and the second only when Cedar allowed every requested
    bit that has a Cedar action. -/
theorem withCedar_hookBlock (e : Env) (pe : PEnv) (agent : Agent) (ctx : Context) (now : Nat)
    (st : CacheState) (hp : pe.prevHook = none) (hfresh : NoServable st now)
    (role : Oid) (c : ClassId) (obj : Oid) (s : Int) (m result : AclMode) (how : How) :
    (hookBlock (withCedar e pe agent ctx now st) ⟨role, c, obj, s, m⟩ result m how).1 = result ∨
    ((hookBlock (withCedar e pe agent ctx now st) ⟨role, c, obj, s, m⟩ result m how).1 = result ||| m ∧
      ∀ i < 32, m &&& bitOf i ≠ 0 → ∀ a, actionForBit i = some a →
        mapHttp (agent (reqFor pe (buildHookInfo e role c obj s m) c obj s ctx a)) = .grant) := by
  simp only [hookBlock, withCedar]
  split
  · exact .inl rfl
  · by_cases hg : (cedarHook pe agent ctx now (AuthInfo.toFull e ⟨role, c, obj, s, m⟩) st).1 = .grant
    · right
      refine ⟨by simp [hg], ?_⟩
      have := cedarHook_grant pe agent ctx now (buildHookInfo e role c obj s m) st _ hp rfl
        (build_readDDL e role c obj s m)
        (cacheSound_of_noServable st now hfresh _) hg
      simpa using this
    · left; simp [hg]

/-- **Finding, end to end**: with pg_authorization enabled, a non-superuser
    passes a `SELECT WITH GRANT OPTION` check (`pg_class_aclcheck`, which is
    "result ≠ 0" with ACLMASK_ANY) on every existing table, whatever Cedar's
    policies say and whether or not Cedar is reachable. This is what
    `has_table_privilege(role, table, 'SELECT WITH GRANT OPTION')` reports.
    Actually issuing GRANT is not affected: `select_best_grantor` reads grant
    options with the unhooked `aclmask_direct` (acl.c). -/
theorem grant_option_reported_for_everyone (e : Env) (pe : PEnv) (agent : Agent) (ctx : Context)
    (now : Nat) (st : CacheState)
    (hp : pe.prevHook = none) (hen : pe.cfg.enabled = true) (hurl : pe.cfg.agentUrl ≠ "")
    (t role : Oid) (r : ClassRow) (hrow : e.cat.classRow t = some r)
    (hsu : e.superuser role = false) (hpsu : pe.superuser role = false) :
    (pgClassAclmask (withCedar e pe agent ctx now st) t role grantOptionSelect .any).1 ≠ 0 := by
  have hW : (grantOptionSelect &&& catalogWriteBits != 0) = false := by decide
  have hm : grantOptionSelect ≠ 0 := by decide
  simp only [pgClassAclmask, withCedar, hrow, hW, hsu, Bool.false_and, Bool.false_eq_true,
    ↓reduceIte, hookBlock]
  split
  · rename_i hsuff
    simp only [sufficient] at hsuff
    intro h0
    simp only at h0
    bv_decide
  · have hc := cedarHook_high_bits_granted pe agent ctx now
      (AuthInfo.toFull e ⟨role, .relation, t, 0, grantOptionSelect⟩) st _ hp hen hpsu hurl rfl
      (build_readDDL e role .relation t 0 grantOptionSelect) grantOptionSelect_low_clear
    simp only [hc, ↓reduceIte]
    intro h0
    bv_decide

end Arcade.Plugin
