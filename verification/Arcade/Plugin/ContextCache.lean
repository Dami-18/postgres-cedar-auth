import Arcade.Plugin.System

/-! # Finding: the cache key ignores the request context

`AuthCacheKey` is (roleid, classid, oid, subid, action). The request context
(day, date, client IP) is not part of it, so a decision Cedar made for one
context is served from the cache for another until `cache_ttl` expires.

This file runs the model on a concrete example: a policy that allows SELECT
only from 10.0.0.7.
-/

namespace Arcade.Plugin.ContextCache
open Arcade.Aclchk Arcade.Plugin

/-- A small database: role 10 = alice, table 100 = public.patient_records. -/
def env0 : Env where
  superuser := fun _ => false
  aclmask   := fun _ _ _ _ => 0
  hook      := none
  cat := { classRow   := fun _ => some ⟨false, false⟩
           attRow     := fun _ _ => none
           nspFound   := fun _ => true
           isTempNsp  := fun _ => false
           typeAclOid := fun t => some t
           objFound   := fun _ _ => true
           roleName   := fun r => if r = 10 then some "alice" else none
           dbName     := fun _ => some "hospital" }
  myDb := 1

def pe0 : PEnv where
  cfg := { enabled := true, agentUrl := "http://cedar-agent:8180", cacheEnabled := true,
           cacheSize := 1024, cacheTtl := 300000000, syncEnabled := true }
  superuser  := fun _ => false
  roleName   := fun r => if r = 10 then some "alice" else none
  resourceId := fun _ _ _ => "public.patient_records"
  prevHook   := none

/-- Cedar's policy: SELECT is allowed only from 10.0.0.7. -/
def agent0 : Agent := fun req =>
  if req.ctx.ip = "10.0.0.7" then .response 200 "{\"decision\":\"Allow\"}"
  else .response 200 "{\"decision\":\"Deny\"}"

def inside  : Context := ⟨"mon", 20261019, "10.0.0.7"⟩
def outside : Context := ⟨"mon", 20261019, "203.0.113.9"⟩

def info0 : AuthorizationInfo := buildHookInfo env0 10 .relation 100 0 ACL_SELECT

/-- First check, from inside the network, at t = 1000 µs. -/
def first := cedarHook pe0 agent0 inside 1000 info0 CacheState.empty
/-- Second check, from outside, one second later, sharing the cache. -/
def second := cedarHook pe0 agent0 outside 1001000 info0 first.2.1

/-- Cedar would deny the outside request. -/
theorem cedar_denies_outside :
    mapHttp (agent0 (reqFor pe0 info0 .relation 100 0 outside "SELECT")) = .deny := by decide

/-- The first check asks Cedar and gets GRANT. -/
theorem first_asks_and_grants : first.1 = .grant ∧ first.2.2.length = 1 := by decide

/-- **The second check is granted from the cache, and Cedar is never asked.** -/
theorem second_granted_from_cache : second.1 = .grant ∧ second.2.2 = [] := by decide

end Arcade.Plugin.ContextCache
