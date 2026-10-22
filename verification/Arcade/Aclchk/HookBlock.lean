import Std.Tactic.BVDecide
import Arcade.Aclchk.Types

/-! # Layer 1: the shared hook block

Models the block inserted at the end of five functions in aclchk.c
(3311–3346, 3478–3514, 3655–3690, 3992–4027, 4155–4190). The copies differ only
in the `AuthInfo` fields they set, so the block takes `info` as a parameter.

The model returns the hook call made (if any) alongside the result, so that
"when is Cedar consulted" and "what is it asked" can be stated as theorems.
-/

namespace Arcade.Aclchk

/-- The `sufficient` computation (e.g. aclchk.c:3321–3324). -/
def sufficient (result mask : AclMode) : How → Bool
  | .all => (result &&& mask) == mask
  | .any => (result &&& mask) != 0

/-- The hook block. Returns the new `result` and the `AuthInfo` passed to the hook, if called. -/
def hookBlock (e : Env) (info : AuthInfo) (result mask : AclMode) (how : How) :
    AclMode × Option AuthInfo :=
  match e.hook with
  | none   => (result, none)                                 -- if (universal_authorization_hook)
  | some h =>
    if sufficient result mask how then (result, none)         -- if (!sufficient)
    else ((if h info = .grant then result ||| mask else result), some info)

/-! ## Theorems (paper §3.2) -/

/-- **Additive**: native bits are never removed. -/
theorem hookBlock_additive (e : Env) (info : AuthInfo) (result mask : AclMode) (how : How) :
    (hookBlock e info result mask how).1 &&& result = result := by
  unfold hookBlock
  split
  · dsimp only
    bv_decide
  · split
    · dsimp only
      bv_decide
    · dsimp only
      split <;> bv_decide

/-- **Sound**: nothing outside `result ∪ mask` is ever granted. -/
theorem hookBlock_sound (e : Env) (info : AuthInfo) (result mask : AclMode) (how : How) :
    (hookBlock e info result mask how).1 &&& ~~~(result ||| mask) = 0 := by
  unfold hookBlock
  split
  · dsimp only
    bv_decide
  · split
    · dsimp only
      bv_decide
    · dsimp only
      split <;> bv_decide

/-- **Fail-closed**: any answer other than GRANT leaves `result` unchanged. -/
theorem hookBlock_fail_closed (e : Env) (h : AuthInfo → HookResult) (he : e.hook = some h)
    (info : AuthInfo) (result mask : AclMode) (how : How) (hng : h info ≠ .grant) :
    (hookBlock e info result mask how).1 = result := by
  unfold hookBlock
  rw [he]
  dsimp only
  split            -- also uses hng to drop the GRANT branch
  · rfl
  · simp

/-- **Post-denial**: the hook is called exactly when it is installed and native
    authorization was insufficient. -/
theorem hookBlock_called_iff (e : Env) (info : AuthInfo) (result mask : AclMode) (how : How) :
    (hookBlock e info result mask how).2.isSome ↔
      (e.hook.isSome ∧ sufficient result mask how = false) := by
  unfold hookBlock
  cases hh : e.hook with
  | none => simp
  | some h =>
    dsimp only
    split <;> simp_all

/-- **Scope**: if the hook is called, it is called with exactly the given `info`. -/
theorem hookBlock_info (e : Env) (info i : AuthInfo) (result mask : AclMode) (how : How)
    (hc : (hookBlock e info result mask how).2 = some i) : i = info := by
  unfold hookBlock at hc
  split at hc
  · simp at hc
  · split at hc
    · simp at hc
    · simp at hc
      exact hc.symm

end Arcade.Aclchk
