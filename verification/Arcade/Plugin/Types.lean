import Arcade.Aclchk.AuthorizationHook

/-! # Types for the pg_authorization.c model

The plugin keeps state (the shared authorization cache) and talks to the Cedar
agent over HTTP. This file defines what the plugin reads (configuration, the
request context), what it sends (`CedarReq`), what comes back (`HttpOutcome`)
and the cache state.

Abstractions:
* Time is a `Nat` (microseconds, as `TimestampTz`). One hook call uses a single
  `now`; the real code reads the clock several times within a call.
* The Cedar agent at a given moment is a function `Agent := CedarReq → HttpOutcome`.
  Theorems that hold "for all agents" hold for a crashed, slow or malicious agent.
* Namespace prefixes (`pg_authorization.namespace`) and JSON escaping are not modelled:
  `CedarReq` carries the logical principal, action, resource and context.
* Name resolution (`get_rel_name` etc.) is abstracted as `PEnv.resourceId`.
-/

namespace Arcade.Plugin
open Arcade.Aclchk

/-- The `context` object sent with every request (pg_authorization.c:502–517). -/
structure Context where
  day  : String    -- get_current_day(): "mon" … "sun"
  date : Nat       -- get_current_date_int(): YYYYMMDD
  ip   : String    -- get_client_ip()
  deriving DecidableEq, Repr

/-- One `POST /v1/is_authorized` request (pg_authorization.c:502–517). -/
structure CedarReq where
  principal    : String     -- User::"<rolename>"
  action       : String     -- Action::"SELECT"
  resourceType : String     -- Table, Column, Schema, …
  resourceId   : String     -- "public.patient_records"
  ctx          : Context
  deriving DecidableEq, Repr

/-- What `curl_easy_perform` produced. -/
inductive HttpOutcome where
  | curlError                                  -- refused, DNS, TLS, timeout
  | response (code : Nat) (body : String)
  deriving DecidableEq, Repr

/-- The Cedar agent at one moment in time. -/
abbrev Agent := CedarReq → HttpOutcome

/-- The GUCs the decision path reads (pg_authorization.c:89–100). -/
structure Config where
  enabled      : Bool     -- pg_authorization.enabled
  agentUrl     : String   -- pg_authorization.cedar_agent_url
  cacheEnabled : Bool     -- pg_authorization.cache_enabled
  cacheSize    : Nat      -- pg_authorization.cache_size
  cacheTtl     : Nat      -- pg_authorization.cache_ttl, in microseconds here
  syncEnabled  : Bool     -- pg_authorization.entity_sync_enabled
  deriving Repr

/-- `AuthCacheKey` (pg_authorization.c:109–115). `action` is the ACL bit
    position here; the C code stores the bit value, which is equivalent. -/
structure CacheKey where
  role     : Oid
  classid  : ClassId
  obj      : Oid
  subid    : Int
  action   : Nat
  deriving DecidableEq, Repr

/-- `AuthCacheEntry` (pg_authorization.c:117–122). -/
structure CacheEntry where
  result    : HookResult
  createdAt : Nat
  expires   : Nat
  deriving DecidableEq, Repr

/-- The shared cache plus `stats->last_cache_reset` (pg_authorization.c:140). -/
structure CacheState where
  entries   : List (CacheKey × CacheEntry)
  lastReset : Nat
  deriving Repr

def CacheState.empty : CacheState := ⟨[], 0⟩

/-- Everything else the plugin reads that we do not verify. -/
structure PEnv where
  cfg        : Config
  superuser  : Oid → Bool                       -- superuser_arg()
  roleName   : Oid → Option String              -- SearchSysCache1(AUTHOID)
  resourceId : ClassId → Oid → Int → String     -- get_rel_name / get_attname / … (993–1090)
  prevHook   : Option (AuthorizationInfo → HookResult)   -- prev_universal_auth_hook

end Arcade.Plugin
