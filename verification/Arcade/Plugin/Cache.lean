import Arcade.Plugin.Types

/-! # The shared authorization cache

Models `reset_auth_cache`, `check_auth_cache` and `update_auth_cache`
(pg_authorization.c:1265–1355). The HTAB is a list of key/entry pairs.
-/

namespace Arcade.Plugin
open Arcade.Aclchk

/-- An entry is served only if not expired and created after the last reset (1289). -/
def isValid (st : CacheState) (now : Nat) (e : CacheEntry) : Bool :=
  decide (now < e.expires) && decide (st.lastReset ≤ e.createdAt)

def lookup (st : CacheState) (k : CacheKey) : Option CacheEntry :=
  (st.entries.find? (fun p => p.1 = k)).map (·.2)

def removeKey (st : CacheState) (k : CacheKey) : CacheState :=
  { st with entries := st.entries.filter (fun p => p.1 ≠ k) }

/-- `reset_auth_cache` (1265–1268): bump the timestamp; entries stay but become invalid. -/
def resetCache (st : CacheState) (now : Nat) : CacheState :=
  { st with lastReset := now }

/-- `check_auth_cache` (1270–1309). IGNORE means "miss". Expired or invalidated
    entries are removed. -/
def checkCache (cfg : Config) (st : CacheState) (now : Nat) (k : CacheKey) :
    HookResult × CacheState :=
  if !cfg.cacheEnabled then (.ignore, st)                         -- 1277
  else match lookup st k with
    | none   => (.ignore, st)
    | some e =>
      if isValid st now e then (e.result, st)                     -- 1289–1292
      else (.ignore, removeKey st k)                              -- 1296–1301

/-- `update_auth_cache` (1311–1355). When full, every entry is dropped and the
    reset timestamp is bumped; then the new entry replaces any old one. -/
def updateCache (cfg : Config) (st : CacheState) (now : Nat) (k : CacheKey) (r : HookResult) :
    CacheState :=
  if !cfg.cacheEnabled then st                                     -- 1318
  else
    let st' := if st.entries.length ≥ cfg.cacheSize                -- 1333
               then { entries := [], lastReset := now } else st     -- 1340–1347
    { st' with entries := (k, ⟨r, now, now + cfg.cacheTtl⟩) :: (removeKey st' k).entries }

/-! ## Theorems -/

/-- The cache never holds more than `max cacheSize 1` entries. -/
theorem updateCache_size (cfg : Config) (st : CacheState) (now : Nat) (k : CacheKey) (r : HookResult)
    (h : st.entries.length ≤ max cfg.cacheSize 1) :
    (updateCache cfg st now k r).entries.length ≤ max cfg.cacheSize 1 := by
  unfold updateCache
  split
  · exact h
  · dsimp only
    split
    · simp [removeKey]; omega
    · rename_i hfull
      simp only [removeKey, List.length_cons]
      have := List.length_filter_le (fun p : CacheKey × CacheEntry => decide (p.1 ≠ k)) st.entries
      omega

/-- A disabled cache never answers. -/
theorem checkCache_disabled (cfg : Config) (st : CacheState) (now : Nat) (k : CacheKey)
    (h : cfg.cacheEnabled = false) : (checkCache cfg st now k).1 = .ignore := by
  simp [checkCache, h]

/-- After a reset at time `t`, no entry created before `t` is ever served. -/
theorem reset_invalidates (st : CacheState) (t now : Nat) (e : CacheEntry) (h : e.createdAt < t) :
    isValid (resetCache st t) now e = false := by
  simp only [isValid, resetCache, Bool.and_eq_false_iff, decide_eq_false_iff_not]
  right
  exact decide_eq_false (by omega)

/-- What "the cache agrees with `expected`" means: every entry that would be
    served agrees with it. -/
def CacheSound (st : CacheState) (now : Nat) (expected : CacheKey → HookResult) : Prop :=
  ∀ k e, (k, e) ∈ st.entries → isValid st now e = true → e.result = expected k

theorem lookup_mem {st : CacheState} {k : CacheKey} {e : CacheEntry} (h : lookup st k = some e) :
    (k, e) ∈ st.entries := by
  unfold lookup at h
  cases hf : st.entries.find? (fun p => p.1 = k) with
  | none => simp [hf] at h
  | some p =>
    simp [hf] at h
    have hm := List.mem_of_find?_eq_some hf
    have hk := List.find?_some hf
    obtain ⟨k', e'⟩ := p
    simp at hk h
    subst hk h
    exact hm

/-- A hit from a sound cache returns the expected answer, and checking keeps
    the cache sound. -/
theorem checkCache_sound (cfg : Config) (st : CacheState) (now : Nat) (k : CacheKey)
    (expected : CacheKey → HookResult) (hs : CacheSound st now expected) :
    ((checkCache cfg st now k).1 = .ignore ∨ (checkCache cfg st now k).1 = expected k) ∧
      CacheSound (checkCache cfg st now k).2 now expected := by
  unfold checkCache
  split
  · exact ⟨.inl rfl, hs⟩
  · split
    · exact ⟨.inl rfl, hs⟩
    · rename_i e he
      split
      · rename_i hv
        exact ⟨.inr (hs k e (lookup_mem he) hv), hs⟩
      · refine ⟨.inl rfl, ?_⟩
        intro k' e' hm hv
        simp [removeKey] at hm
        exact hs k' e' hm.1 (by simpa [isValid, removeKey] using hv)

/-- Storing the expected answer keeps the cache sound. -/
theorem updateCache_sound (cfg : Config) (st : CacheState) (now : Nat) (k : CacheKey)
    (expected : CacheKey → HookResult) (hs : CacheSound st now expected) :
    CacheSound (updateCache cfg st now k (expected k)) now expected := by
  unfold updateCache
  split
  · exact hs
  · dsimp only
    intro k' e' hm hv
    simp only [List.mem_cons, removeKey, List.mem_filter] at hm
    rcases hm with hnew | ⟨hold, hne⟩
    · simp at hnew; obtain ⟨rfl, rfl⟩ := hnew; rfl
    · split at hold
      · simp at hold
      · rename_i hlt
        have hnf : ¬ cfg.cacheSize ≤ st.entries.length := by omega
        exact hs k' e' hold (by simpa [isValid, hnf] using hv)

end Arcade.Plugin
