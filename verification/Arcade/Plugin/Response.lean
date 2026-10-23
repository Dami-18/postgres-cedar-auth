import Arcade.Plugin.Types

/-! # HTTP response mapping

Models the end of `cedar_call_is_authorized_internal` (pg_authorization.c:541–581):
a 200 response whose body contains `"Allow"` is GRANT, else one containing
`"Deny"` is DENY; everything else, including transport errors, is IGNORE.
The check is a substring search (`strstr`), not a JSON parse.
-/

namespace Arcade.Plugin
open Arcade.Aclchk

/-- `strstr(hay, needle) != NULL` on character lists. -/
def listContains (pat : List Char) : List Char → Bool
  | []      => pat.isEmpty
  | c :: cs => pat.isPrefixOf (c :: cs) || listContains pat cs

def strContains (hay pat : String) : Bool := listContains pat.toList hay.toList

def quotedAllow : String := "\"Allow\""
def quotedDeny  : String := "\"Deny\""

/-- pg_authorization.c:541–581. -/
def mapHttp : HttpOutcome → HookResult
  | .curlError => .ignore                                          -- 544–547
  | .response code body =>
    if code = 200 then                                             -- 566
      if strContains body quotedAllow then .grant                  -- 567–569
      else if strContains body quotedDeny then .deny               -- 570–572
      else .ignore                                                 -- 573–575
    else .ignore                                                   -- 576–581

/-- **Fail-closed at the transport layer**: GRANT only from a 200 response
    whose body contains `"Allow"`. -/
theorem mapHttp_grant_iff (o : HttpOutcome) :
    mapHttp o = .grant ↔ ∃ body, o = .response 200 body ∧ strContains body quotedAllow = true := by
  cases o with
  | curlError => simp [mapHttp]
  | response code body =>
    unfold mapHttp
    by_cases hc : code = 200
    · subst hc
      by_cases ha : strContains body quotedAllow = true
      · simp [ha]
      · simp only [ha, ite_true, Bool.false_eq_true, ite_false]
        constructor
        · intro h; split at h <;> simp at h
        · rintro ⟨b, hb, hb2⟩; cases hb; simp_all
    · simp [hc]

theorem mapHttp_curlError : mapHttp .curlError = .ignore := rfl

theorem mapHttp_not_200 (code : Nat) (body : String) (h : code ≠ 200) :
    mapHttp (.response code body) = .ignore := by
  simp [mapHttp, h]

/-- The normal agent responses map as intended. -/
theorem mapHttp_allow : mapHttp (.response 200 "{\"decision\":\"Allow\"}") = .grant := by decide
theorem mapHttp_deny  : mapHttp (.response 200 "{\"decision\":\"Deny\"}") = .deny := by decide

/-- **Finding**: a Deny whose diagnostics mention a policy whose id is `Allow`
    is read as GRANT, because the whole body is searched for `"Allow"`. -/
theorem mapHttp_deny_with_allow_policy_id :
    mapHttp (.response 200
      "{\"decision\":\"Deny\",\"diagnostics\":{\"reason\":[\"Allow\"],\"errors\":[]}}") = .grant := by
  decide

end Arcade.Plugin
