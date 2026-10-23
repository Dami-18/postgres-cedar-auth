import Arcade.Plugin.Types

/-! # Finding: a stale decision survives a policy change (state machine)

`update_auth_cache` stamps a new entry with the time it is *stored*
(pg_authorization.c:1353), not the time Cedar was *asked*. A request that is in
flight while the policy changes and the cache is reset therefore stores the old
answer with a timestamp after the reset, and that answer is served until
`cache_ttl` expires.

This file is a small state machine over one backend's in-flight request, the
shared cache, and the agent's policy version. Each step advances the clock by
one tick, so steps happen at distinct times. TTL expiry is left out: it only
shortens how long an entry is served.

`stampAtStart = false` is the current code; `true` is the proposed fix
(stamp with the time the request was sent).
-/

namespace Arcade.Plugin.Race
open Arcade.Aclchk Arcade.Plugin

/-- What Cedar answers for a cache key under policy version `v`. -/
abbrev PolicyFn := Nat → CacheKey → HookResult

structure State where
  entries   : List (CacheKey × CacheEntry)
  lastReset : Nat
  clock     : Nat
  policy    : Nat
  /-- An in-flight request: the key, Cedar's answer, and when it was sent. -/
  pending   : Option (CacheKey × HookResult × Nat)

def State.init : State := ⟨[], 0, 0, 0, none⟩

inductive Action where
  /-- Cache miss: send the request; Cedar answers under the current policy (1095–1099). -/
  | ask (k : CacheKey)
  /-- `update_auth_cache` with the answer (1099–1100). -/
  | finish
  /-- An admin changes a policy; the agent calls `pg_authorization_cache_reset()` (1265). -/
  | changePolicy

def insertEntry (es : List (CacheKey × CacheEntry)) (k : CacheKey) (e : CacheEntry) :
    List (CacheKey × CacheEntry) :=
  (k, e) :: es.filter (fun p => p.1 ≠ k)

def step (pol : PolicyFn) (stampAtStart : Bool) (s : State) : Action → State
  | .ask k        => { s with clock := s.clock + 1, pending := some (k, pol s.policy k, s.clock) }
  | .finish       =>
    match s.pending with
    | none => { s with clock := s.clock + 1 }
    | some (k, r, start) =>
      { s with clock := s.clock + 1, pending := none,
               entries := insertEntry s.entries k
                 ⟨r, if stampAtStart then start else s.clock, 0⟩ }
  | .changePolicy => { s with clock := s.clock + 1, policy := s.policy + 1,
                              lastReset := s.clock + 1 }

def run (pol : PolicyFn) (stampAtStart : Bool) (s : State) (as : List Action) : State :=
  as.foldl (step pol stampAtStart) s

/-- What a lookup serves: the entry for `k`, if created at or after the last reset (1289). -/
def served (s : State) (k : CacheKey) : Option HookResult :=
  match s.entries.find? (fun p => p.1 = k) with
  | some (_, e) => if s.lastReset ≤ e.createdAt then some e.result else none
  | none        => none

/-! ## The bug -/

def k0 : CacheKey := ⟨10, .relation, 100, 0, 1⟩

/-- Policy 0 allows; every later policy denies. -/
def revoke : PolicyFn := fun v _ => if v = 0 then .grant else .deny

/-- **Current code**: ask under policy 0, the policy changes (and the cache is
    reset) while the request is in flight, then the answer is stored.
    The cache now serves GRANT although the current policy denies. -/
theorem stale_grant_served :
    let s := run revoke false State.init [.ask k0, .changePolicy, .finish]
    served s k0 = some .grant ∧ revoke s.policy k0 = .deny := by
  decide

/-- **With the fix** the same trace serves nothing: the entry predates the reset. -/
theorem fixed_same_trace :
    served (run revoke true State.init [.ask k0, .changePolicy, .finish]) k0 = none := by
  decide

/-! ## The fix is correct for every trace -/

/-- The invariant: anything the cache would serve, and any in-flight answer
    that would count as fresh, agrees with the current policy. -/
def Inv (pol : PolicyFn) (s : State) : Prop :=
  (∀ k e, (k, e) ∈ s.entries → s.lastReset ≤ e.createdAt → e.result = pol s.policy k) ∧
  (∀ k r start, s.pending = some (k, r, start) → s.lastReset ≤ start → r = pol s.policy k) ∧
  (∀ k e, (k, e) ∈ s.entries → e.createdAt ≤ s.clock) ∧
  (∀ k r start, s.pending = some (k, r, start) → start ≤ s.clock)

theorem inv_init (pol : PolicyFn) : Inv pol State.init := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> intros <;> simp_all [State.init]

theorem mem_insertEntry {es : List (CacheKey × CacheEntry)} {k k' : CacheKey} {e e' : CacheEntry}
    (h : (k', e') ∈ insertEntry es k e) : (k' = k ∧ e' = e) ∨ (k', e') ∈ es := by
  simp only [insertEntry, List.mem_cons, Prod.mk.injEq, List.mem_filter] at h
  rcases h with h | ⟨h, _⟩
  · exact .inl h
  · exact .inr h

theorem inv_step (pol : PolicyFn) (s : State) (a : Action) (h : Inv pol s) :
    Inv pol (step pol true s a) := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  cases a with
  | ask k =>
    refine ⟨h1, ?_, ?_, ?_⟩
    · intro k' r start hp _
      simp [step] at hp
      obtain ⟨rfl, rfl, rfl⟩ := hp
      rfl
    · intro k' e hm; have := h3 k' e hm; simp [step]; omega
    · intro k' r start hp; simp [step] at hp ⊢; omega
  | finish =>
    simp only [step]
    split
    · exact ⟨h1, fun _ _ _ hp => by simp_all, fun k e hm => Nat.le_succ_of_le (h3 k e hm),
             fun _ _ _ hp => by simp_all⟩
    · rename_i k r start hpend
      refine ⟨?_, by simp, ?_, by simp⟩
      · intro k' e' hm hfresh
        rcases mem_insertEntry hm with ⟨rfl, rfl⟩ | hold
        · exact h2 k' r start hpend hfresh
        · exact h1 k' e' hold hfresh
      · intro k' e' hm
        rcases mem_insertEntry hm with ⟨rfl, rfl⟩ | hold
        · have := h4 _ _ _ hpend; simp; omega
        · have := h3 k' e' hold; show e'.createdAt ≤ s.clock + 1; omega
  | changePolicy =>
    refine ⟨?_, ?_, ?_, ?_⟩
    · intro k e hm hfresh
      have := h3 k e hm
      simp [step] at hfresh; omega
    · intro k r start hp hfresh
      have := h4 k r start hp
      simp [step] at hfresh; omega
    · intro k e hm; have := h3 k e hm; simp [step]; omega
    · intro k r start hp; have := h4 k r start hp; simp [step]; omega

theorem inv_run (pol : PolicyFn) : ∀ (as : List Action) (s : State), Inv pol s →
    Inv pol (run pol true s as) := by
  intro as
  induction as with
  | nil => intro s h; exact h
  | cons a as ih => intro s h; exact ih _ (inv_step pol s a h)

/-- **The fix is correct**: after any sequence of requests, stores and policy
    changes, everything the cache serves agrees with the current policy. -/
theorem fixed_never_stale (pol : PolicyFn) (as : List Action) (k : CacheKey) (r : HookResult)
    (h : served (run pol true State.init as) k = some r) :
    r = pol (run pol true State.init as).policy k := by
  have ⟨h1, _, _, _⟩ := inv_run pol as State.init (inv_init pol)
  unfold served at h
  split at h
  · rename_i k' e hf
    split at h
    · rename_i hfresh
      cases h
      have hm := List.mem_of_find?_eq_some hf
      have hk := List.find?_some hf
      simp at hk
      subst hk
      exact h1 k' e hm hfresh
    · cases h
  · cases h

end Arcade.Plugin.Race
