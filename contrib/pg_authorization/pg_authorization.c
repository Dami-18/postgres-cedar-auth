/* -------------------------------------------------------------------------
 *
 * pg_authorization.c
 *
 * PostgreSQL External Authorization Plugin
 *
 * This extension externalizes PostgreSQL's authorization layer, allowing
 * authorization decisions to be delegated to external policy engines like
 * Cedar, OPA, or custom authorization services.
 *
 * Features:
 * - Intercepts all ACL permission checks via aclchk.c hooks
 * - Intercepts DDL operations via object_access_hook (for Entity Sync)
 * - Intercepts utility commands via ProcessUtility_hook (for Audit/Sync)
 * - Entity synchronization: syncs Users, Tables, Databases to Cedar Agent
 * - Cedar-compatible request format (principal/action/resource)
 * - Configurable via GUC variables
 * - Authorization caching to reduce network overhead
 * - Persistent CURL connections for improved latency
 *
 * Cedar Agent API Integration:
 * - Authorization: POST /v1/is_authorized
 * - Entity sync (create/update): PUT /v1/data/single/{entity_id}
 * - Entity sync (delete): DELETE /v1/data/single/{entity_id}
 *
 * Copyright (c) 2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/pg_authorization/pg_authorization.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include <curl/curl.h>
#include <time.h>

#include "access/htup_details.h"
#include "access/relation.h"
#include "access/table.h"
#include "catalog/objectaccess.h"
#include "utils/rel.h"
#include "nodes/parsenodes.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "commands/dbcommands.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "nodes/nodes.h"
#include "parser/parse_relation.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/authorization_hook.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/hsearch.h"
#include "common/hashfn.h"
#include "utils/timestamp.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#include "storage/lwlock.h"

PG_MODULE_MAGIC;

/* SQL-callable functions */
PG_FUNCTION_INFO_V1(pg_authorization_is_enabled);
PG_FUNCTION_INFO_V1(pg_authorization_stats);
PG_FUNCTION_INFO_V1(pg_authorization_reset_stats);
PG_FUNCTION_INFO_V1(pg_authorization_sync_entity);
PG_FUNCTION_INFO_V1(pg_authorization_cache_stats);
PG_FUNCTION_INFO_V1(pg_authorization_cache_reset);
PG_FUNCTION_INFO_V1(pg_authorization_flush_syscache);

/* --------------------------------------------------------------------------
 * GUC variables
 * --------------------------------------------------------------------------
 */
static char *cedar_agent_url = NULL;     /* Base URL for Cedar Agent */
static char *cedar_namespace = NULL;     /* Namespace for Cedar entities */
static int cedar_request_timeout = 5000; /* Timeout in milliseconds */
static bool cedar_authorization_enabled = true;
static bool cedar_entity_sync_enabled = true;
static bool cedar_log_decisions = false;
static bool cedar_collect_stats = true;

/* Caching GUCs */
static bool cedar_cache_enabled = true;
static int cedar_cache_size = 1024;
static int cedar_cache_ttl = 300; /* seconds */

/* HTTPS/SSL GUCs */
static bool cedar_use_https = false;
static bool cedar_ssl_verify_peer = false;
static char *cedar_ssl_cert_file = NULL;
static char *cedar_ssl_key_file = NULL;

/* Cache structures */
typedef struct AuthCacheKey {
  Oid roleid;
  Oid classid;
  Oid resource_oid;
  int32 subid;
  int32 action; /* e.g. AclMode bit, or hash(command_tag) */
} AuthCacheKey;

typedef struct AuthCacheEntry {
  AuthCacheKey key;
  AuthorizationResult result;
  TimestampTz created_at;
  TimestampTz expires;
} AuthCacheEntry;

/* --------------------------------------------------------------------------
 * Statistics counters (in shared memory)
 * --------------------------------------------------------------------------
 */
typedef struct pg_auth_stats_t
{
	long auth_requests;
	long auth_grants;
	long auth_denies;
	long auth_ignores;
	long auth_errors;
	double auth_total_time;
	double auth_remote_time;
	long sync_requests;
	long sync_successes;
	long sync_failures;
	TimestampTz last_cache_reset;
} pg_auth_stats_t;

static pg_auth_stats_t *stats = NULL;

/* Cache statistics (also in shared memory) */
typedef struct pg_cache_stats_t
{
	long hits;
	long misses;
	long evictions;
} pg_cache_stats_t;

static pg_cache_stats_t *cache_stats = NULL;

/* --------------------------------------------------------------------------
 * Internal state
 * --------------------------------------------------------------------------
 */
static CURL *persistent_curl = NULL;
static HTAB *auth_cache = NULL;
static LWLock *auth_cache_lock = NULL;
static shmem_request_hook_type prev_shmem_request_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/* --------------------------------------------------------------------------
 * Shared Memory Management
 * --------------------------------------------------------------------------
 */
static size_t
pg_auth_shmem_size(void)
{
	size_t size;

	size = MAXALIGN(sizeof(pg_auth_stats_t));
	size = add_size(size, MAXALIGN(sizeof(pg_cache_stats_t)));
	size = add_size(size, hash_estimate_size(cedar_cache_size, sizeof(AuthCacheEntry)));

	return size;
}

static void
pg_auth_shmem_request(void)
{
	if (prev_shmem_request_hook)
		prev_shmem_request_hook();

	RequestAddinShmemSpace(pg_auth_shmem_size());
	RequestNamedLWLockTranche("pg_authorization", 1);
}

static void
pg_auth_shmem_startup(void)
{
	bool found;
	HASHCTL ctl;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	stats = (pg_auth_stats_t *)
		ShmemInitStruct("pg_authorization_stats",
						sizeof(pg_auth_stats_t),
						&found);

	if (!found)
	{
		memset(stats, 0, sizeof(pg_auth_stats_t));
	}

	cache_stats = (pg_cache_stats_t *)
		ShmemInitStruct("pg_authorization_cache_stats",
						sizeof(pg_cache_stats_t),
						&found);

	if (!found)
	{
		memset(cache_stats, 0, sizeof(pg_cache_stats_t));
	}

	/* Initialize shared auth cache */
	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(AuthCacheKey);
	ctl.entrysize = sizeof(AuthCacheEntry);
	auth_cache = ShmemInitHash("pg_authorization_cache",
								cedar_cache_size,
								cedar_cache_size,
								&ctl,
								HASH_ELEM | HASH_BLOBS);

	auth_cache_lock = &(GetNamedLWLockTranche("pg_authorization"))[0].lock;

	LWLockRelease(AddinShmemInitLock);
}

/* --------------------------------------------------------------------------
 * Saved hook entries (for chaining)
 * --------------------------------------------------------------------------
 */
static object_access_hook_type prev_object_access_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static universal_authorization_hook_type prev_universal_auth_hook = NULL;

/* --------------------------------------------------------------------------
 * Forward declarations
 * --------------------------------------------------------------------------
 */
void _PG_init(void);
void _PG_fini(void);

static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg);

static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc);

static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info);

static void reset_auth_cache(void);
static AuthorizationResult check_auth_cache(Oid roleid, Oid classid, Oid resource_oid,
                                           int32 subid, int32 action);
static void update_auth_cache(Oid roleid, Oid classid, Oid resource_oid,
                             int32 subid, int32 action, AuthorizationResult result);
static void configure_curl_ssl(CURL *curl_handle);

/* --------------------------------------------------------------------------
 * Helper: JSON string escaping
 * --------------------------------------------------------------------------
 */
static char *json_escape_string(const char *str) {
  StringInfoData buf;
  const char *p;

  if (str == NULL)
    return pstrdup("");

  initStringInfo(&buf);

  for (p = str; *p; p++) {
    switch (*p) {
    case '"':
      appendStringInfoString(&buf, "\\\"");
      break;
    case '\\':
      appendStringInfoString(&buf, "\\\\");
      break;
    case '\n':
      appendStringInfoString(&buf, "\\n");
      break;
    case '\r':
      appendStringInfoString(&buf, "\\r");
      break;
    case '\t':
      appendStringInfoString(&buf, "\\t");
      break;
    case '\b':
      appendStringInfoString(&buf, "\\b");
      break;
    case '\f':
      appendStringInfoString(&buf, "\\f");
      break;
    default:
      if ((unsigned char)*p < 0x20) {
        /* Control character - escape as \uXXXX */
        appendStringInfo(&buf, "\\u%04x", (unsigned char)*p);
      } else {
        appendStringInfoChar(&buf, *p);
      }
      break;
    }
  }

  return buf.data;
}

/* --------------------------------------------------------------------------
 * Helper: Get current day as lowercase string (mon, tue, wed, etc.)
 * --------------------------------------------------------------------------
 */
static const char *get_current_day(void) {
  static const char *days[] = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"};
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  return days[tm_info->tm_wday];
}

/* --------------------------------------------------------------------------
 * Helper: Get current date as YYYYMMDD integer
 * --------------------------------------------------------------------------
 */
static int get_current_date_int(void) {
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  return (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 +
         tm_info->tm_mday;
}

/* --------------------------------------------------------------------------
 * Helper: Get client IP address
 * --------------------------------------------------------------------------
 */
static const char *get_client_ip(void) {
  if (MyProcPort && MyProcPort->remote_host) {
    if (strcmp(MyProcPort->remote_host, "[local]") == 0 || 
        strcmp(MyProcPort->remote_host, "unknown") == 0)
      return "127.0.0.1";
    return MyProcPort->remote_host;
  }
  return "127.0.0.1";
}

/* --------------------------------------------------------------------------
 * Helper: Map a single PostgreSQL AclMode bit to Cedar action string
 * --------------------------------------------------------------------------
 */
static const char *get_cedar_action_for_bit(AclMode bit) {
  if (bit == ACL_SELECT)
    return "SELECT";
  if (bit == ACL_INSERT)
    return "INSERT";
  if (bit == ACL_UPDATE)
    return "UPDATE";
  if (bit == ACL_DELETE)
    return "DELETE";
  if (bit == ACL_TRUNCATE)
    return "TRUNCATE";
  if (bit == ACL_REFERENCES)
    return "REFERENCES";
  if (bit == ACL_TRIGGER)
    return "TRIGGER";
  if (bit == ACL_EXECUTE)
    return "EXECUTE";
  if (bit == ACL_USAGE)
    return "USAGE";
  if (bit == ACL_CREATE)
    return "CREATE";
  if (bit == ACL_CREATE_TEMP)
    return "CREATE_TEMP";
  if (bit == ACL_CONNECT)
    return "CONNECT";
  if (bit == ACL_SET)
    return "SET";
  if (bit == ACL_ALTER_SYSTEM)
    return "ALTER_SYSTEM";
  if (bit == ACL_MAINTAIN)
    return "MAINTAIN";
  return NULL;
}

/* --------------------------------------------------------------------------
 * libcurl callback for response data
 * --------------------------------------------------------------------------
 */
static size_t
pg_auth_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  StringInfo buf = (StringInfo)userp;

  appendBinaryStringInfo(buf, (char *)contents, realsize);
  return realsize;
}

/* --------------------------------------------------------------------------
 * Helper: Configure SSL/TLS options for CURL handle
 * --------------------------------------------------------------------------
 */
static void
configure_curl_ssl(CURL *curl_handle)
{
  if (!cedar_use_https)
    return;

  /* Configure SSL/TLS certificate verification */
  if (cedar_ssl_verify_peer)
  {
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
  }
  else
  {
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
  }

  /* Configure client certificate for mTLS if provided */
  if (cedar_ssl_cert_file && cedar_ssl_cert_file[0] != '\0')
  {
    curl_easy_setopt(curl_handle, CURLOPT_SSLCERT, cedar_ssl_cert_file);
    curl_easy_setopt(curl_handle, CURLOPT_SSLCERTTYPE, "PEM");
  }

  /* Configure client private key for mTLS if provided */
  if (cedar_ssl_key_file && cedar_ssl_key_file[0] != '\0')
  {
    curl_easy_setopt(curl_handle, CURLOPT_SSLKEY, cedar_ssl_key_file);
    curl_easy_setopt(curl_handle, CURLOPT_SSLKEYTYPE, "PEM");
  }
}

/* --------------------------------------------------------------------------
 * Cedar Agent: Call /v1/is_authorized endpoint
 * --------------------------------------------------------------------------
 */
static AuthorizationResult cedar_call_is_authorized_internal(const char *principal_type,
                                                            const char *principal_id,
                                                            const char *action,
                                                            const char *resource_type,
                                                            const char *resource_id) {
  CURLcode res;
  StringInfoData request_body;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  AuthorizationResult result = PG_AUTH_RESULT_IGNORE;

  /* Use persistent handle if possible */
  if (persistent_curl == NULL) {
    persistent_curl = curl_easy_init();
    if (!persistent_curl) {
      ereport(WARNING, (errmsg("pg_authorization: failed to initialize curl")));
      if (cedar_collect_stats) stats->auth_errors++;
      return PG_AUTH_RESULT_IGNORE;
    }
  } else {
    /* Reset handle for new request but keep connections open */
    curl_easy_reset(persistent_curl);
  }

  initStringInfo(&request_body);
  initStringInfo(&response_body);
  initStringInfo(&url);

  /* Build URL */
  appendStringInfoString(&url, cedar_agent_url);
  if (url.len > 0 && url.data[url.len - 1] == '/')
    url.data[--url.len] = '\0';

  if (url.len >= 3 &&
      url.data[url.len - 3] == '/' &&
      url.data[url.len - 2] == 'v' &&
      url.data[url.len - 1] == '1')
    appendStringInfoString(&url, "/is_authorized");
  else
    appendStringInfoString(&url, "/v1/is_authorized");

  /* Build JSON request body */
  {
    char *escaped_principal = json_escape_string(principal_id);
    char *escaped_resource = json_escape_string(resource_id);
    char *ns_prefix = (cedar_namespace && cedar_namespace[0] != '\0') ? psprintf("%s::", cedar_namespace) : NULL;
    const char *ns_str = ns_prefix ? ns_prefix : "";

    appendStringInfo(&request_body,
                     "{"
                     "\"principal\":\"%s%s::\\\"%s\\\"\","
                     "\"action\":\"%sAction::\\\"%s\\\"\","
                     "\"resource\":\"%s%s::\\\"%s\\\"\","
                     "\"context\":{"
                     "\"day\":\"%s\","
                     "\"date\":%d,"
                     "\"ip\":{\"__extn\":{\"fn\":\"ip\",\"arg\":\"%s\"}}"
                     "}"
                     "}",
                     ns_str, principal_type, escaped_principal,
                     ns_str, action,
                     ns_str, resource_type, escaped_resource,
                     get_current_day(), get_current_date_int(),
                     get_client_ip());

    pfree(escaped_principal);
    pfree(escaped_resource);
    if (ns_prefix) pfree(ns_prefix);
  }

  /* Setup curl request */
  curl_easy_setopt(persistent_curl, CURLOPT_URL, url.data);
  curl_easy_setopt(persistent_curl, CURLOPT_POST, 1L);
  curl_easy_setopt(persistent_curl, CURLOPT_POSTFIELDS, request_body.data);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(persistent_curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(persistent_curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);
  curl_easy_setopt(persistent_curl, CURLOPT_TCP_KEEPALIVE, 1L);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "X-Cedar-Write-Origin: db-entity-sync");
  curl_easy_setopt(persistent_curl, CURLOPT_HTTPHEADER, headers);

  /* Configure SSL/TLS if HTTPS is enabled */
  configure_curl_ssl(persistent_curl);

  res = curl_easy_perform(persistent_curl);

  if (res != CURLE_OK) {
    ereport(LOG, (errmsg("pg_authorization: curl request failed: %s",
                             curl_easy_strerror(res))));
    if (cedar_collect_stats) stats->auth_errors++;
    result = PG_AUTH_RESULT_IGNORE;
  } else {
    double total_time;
    double start_transfer_time;
    double pre_transfer_time;

    curl_easy_getinfo(persistent_curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(persistent_curl, CURLINFO_TOTAL_TIME, &total_time);
    curl_easy_getinfo(persistent_curl, CURLINFO_STARTTRANSFER_TIME, &start_transfer_time);
    curl_easy_getinfo(persistent_curl, CURLINFO_PRETRANSFER_TIME, &pre_transfer_time);

    if (cedar_collect_stats)
    {
        stats->auth_total_time += total_time;
        stats->auth_remote_time += (start_transfer_time - pre_transfer_time);
    }

    appendStringInfoChar(&response_body, '\0');

    if (response_code == 200) {
      if (strstr(response_body.data, "\"Allow\"") != NULL) {
        result = PG_AUTH_RESULT_GRANT;
        if (cedar_collect_stats) stats->auth_grants++;
      } else if (strstr(response_body.data, "\"Deny\"") != NULL) {
        result = PG_AUTH_RESULT_DENY;
        if (cedar_collect_stats) stats->auth_denies++;
      } else {
        result = PG_AUTH_RESULT_IGNORE;
        if (cedar_collect_stats) stats->auth_ignores++;
      }
    } else {
      ereport(WARNING, (errmsg("pg_authorization: Cedar Agent returned status %ld", response_code)));
      if (cedar_collect_stats) stats->auth_errors++;
      result = PG_AUTH_RESULT_IGNORE;
    }
  }

  curl_slist_free_all(headers);
  pfree(request_body.data);
  pfree(response_body.data);
  pfree(url.data);

  return result;
}

/*
 * NOTE: We intentionally do NOT provide a string-keyed caching wrapper here.
 * The hot path uses Oid/int cache keys so we can avoid name lookups unless
 * we actually need to call the remote agent.
 */

/* --------------------------------------------------------------------------
 * Cedar Agent: Sync entity to /v1/data/single endpoint (PUT)
 * --------------------------------------------------------------------------
 */
static bool cedar_sync_entity_upsert(const char *entity_type,
                                     const char *entity_id) {
  CURLcode res;
  StringInfoData request_body;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  char *url_escaped_id;
  char *json_escaped_id;
  bool success = false;
  bool has_v1;

  /* Reset cache on any sync attempt as the remote state is changing */
  reset_auth_cache();

  /* Check if sync is enabled and URL is configured */
  if (!cedar_entity_sync_enabled || cedar_agent_url == NULL ||
      cedar_agent_url[0] == '\0')
    return false;

  if (cedar_collect_stats) stats->sync_requests++;

  if (persistent_curl == NULL) {
    persistent_curl = curl_easy_init();
    if (!persistent_curl) return false;
  } else {
    curl_easy_reset(persistent_curl);
  }

  initStringInfo(&request_body);
  initStringInfo(&response_body);
  initStringInfo(&url);

  {
    char *ns_prefix = (cedar_namespace && cedar_namespace[0] != '\0') ? psprintf("%s::", cedar_namespace) : NULL;
    const char *ns_str = ns_prefix ? ns_prefix : "";
    char *full_uid;

    full_uid = psprintf("%s%s::\"%s\"", ns_str, entity_type, entity_id);

    appendStringInfoString(&url, cedar_agent_url);
    if (url.len > 0 && url.data[url.len - 1] == '/')
      url.data[--url.len] = '\0';

    has_v1 = (url.len >= 3 &&
              url.data[url.len - 3] == '/' &&
              url.data[url.len - 2] == 'v' &&
              url.data[url.len - 1] == '1');

    url_escaped_id = curl_easy_escape(persistent_curl, full_uid, (int)strlen(full_uid));
    if (has_v1)
      appendStringInfo(&url, "/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);
    else
      appendStringInfo(&url, "/v1/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);

    json_escaped_id = json_escape_string(entity_id);
    appendStringInfoString(&request_body, "[{");
    appendStringInfo(&request_body, "\"uid\":{\"type\":\"%s%s\",\"id\":\"%s\"}",
                     ns_str, entity_type, json_escaped_id);
    appendStringInfoString(&request_body, ",\"attrs\":{},\"parents\":[]}]");

    pfree(json_escaped_id);
    pfree(full_uid);
    if (ns_prefix) pfree(ns_prefix);
  }

  curl_easy_setopt(persistent_curl, CURLOPT_URL, url.data);
  curl_easy_setopt(persistent_curl, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(persistent_curl, CURLOPT_POSTFIELDS, request_body.data);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(persistent_curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(persistent_curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "X-Cedar-Write-Origin: db-entity-sync");
  curl_easy_setopt(persistent_curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(persistent_curl);

  if (res != CURLE_OK) {
    ereport(WARNING, (errmsg("pg_authorization: entity sync failed: %s", curl_easy_strerror(res))));
    if (cedar_collect_stats) stats->sync_failures++;
  } else {
    curl_easy_getinfo(persistent_curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code >= 200 && response_code < 300) {
      if (cedar_collect_stats) stats->sync_successes++;
      success = true;
    } else if (response_code == 409) {
      if (cedar_collect_stats) stats->sync_successes++;
      success = true;
    } else {
      if (cedar_collect_stats) stats->sync_failures++;
    }
  }

  if (url_escaped_id) curl_free(url_escaped_id);
  curl_slist_free_all(headers);
  pfree(request_body.data);
  pfree(response_body.data);
  pfree(url.data);

  return success;
}

/* --------------------------------------------------------------------------
 * Cedar Agent: Delete entity from /v1/data/single endpoint (DELETE)
 * --------------------------------------------------------------------------
 */
static bool cedar_sync_entity_delete(const char *entity_type,
                                     const char *entity_id) {
  CURLcode res;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  char *url_escaped_id;
  bool success = false;
  bool has_v1;

  /* Reset cache on any sync attempt as the remote state is changing */
  reset_auth_cache();

  if (!cedar_entity_sync_enabled || cedar_agent_url == NULL ||
      cedar_agent_url[0] == '\0')
    return false;

  if (cedar_collect_stats) stats->sync_requests++;

  if (persistent_curl == NULL) {
    persistent_curl = curl_easy_init();
    if (!persistent_curl) return false;
  } else {
    curl_easy_reset(persistent_curl);
  }

  initStringInfo(&response_body);
  initStringInfo(&url);

  {
    char *ns_prefix = (cedar_namespace && cedar_namespace[0] != '\0') ? psprintf("%s::", cedar_namespace) : NULL;
    const char *ns_str = ns_prefix ? ns_prefix : "";
    char *full_uid;

    full_uid = psprintf("%s%s::\"%s\"", ns_str, entity_type, entity_id);

    appendStringInfoString(&url, cedar_agent_url);
    if (url.len > 0 && url.data[url.len - 1] == '/')
      url.data[--url.len] = '\0';

    has_v1 = (url.len >= 3 &&
              url.data[url.len - 3] == '/' &&
              url.data[url.len - 2] == 'v' &&
              url.data[url.len - 1] == '1');

    url_escaped_id = curl_easy_escape(persistent_curl, full_uid, (int)strlen(full_uid));
    if (has_v1)
      appendStringInfo(&url, "/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);
    else
      appendStringInfo(&url, "/v1/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);

    if (ns_prefix) pfree(ns_prefix);
    pfree(full_uid);
  }

  curl_easy_setopt(persistent_curl, CURLOPT_URL, url.data);
  curl_easy_setopt(persistent_curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(persistent_curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(persistent_curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(persistent_curl, CURLOPT_HTTPHEADER, headers);

  /* Configure SSL/TLS if HTTPS is enabled */
  configure_curl_ssl(persistent_curl);

  res = curl_easy_perform(persistent_curl);

  if (res != CURLE_OK) {
    ereport(WARNING, (errmsg("pg_authorization: entity delete failed: %s", curl_easy_strerror(res))));
    if (cedar_collect_stats) stats->sync_failures++;
  } else {
    curl_easy_getinfo(persistent_curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code >= 200 && response_code < 300) {
      if (cedar_collect_stats) stats->sync_successes++;
      success = true;
    } else if (response_code == 404) {
      if (cedar_collect_stats) stats->sync_successes++;
      success = true;
    } else {
      if (cedar_collect_stats) stats->sync_failures++;
    }
  }

  if (url_escaped_id) curl_free(url_escaped_id);
  curl_slist_free_all(headers);
  pfree(response_body.data);
  pfree(url.data);

  return success;
}

/* --------------------------------------------------------------------------
 * Universal authorization hook callback
 * --------------------------------------------------------------------------
 */
static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info) {
  AuthorizationResult result = PG_AUTH_RESULT_GRANT;
  AclMode required_perms = 0;
  bool check_perms_loop = false;
  char *resolved_rolename = NULL;
  const char *rolename = auth_info->rolename;
  const char *resource_type = NULL;
  char *resource_id_str = NULL;
  bool have_resource_id = false;
  bool have_resolved_rolename = false;
  Oid classid = InvalidOid;
  Oid resource_oid = InvalidOid;
  int32 subid = 0;

  if (cedar_log_decisions) {
    ereport(LOG, (errmsg("pg_authorization: hook called for event %d", auth_info->event_type)));
  }

  if (prev_universal_auth_hook) {
    result = prev_universal_auth_hook(auth_info);
    if (result != PG_AUTH_RESULT_IGNORE)
      return result;
  }

  if (!cedar_authorization_enabled)
    return PG_AUTH_RESULT_IGNORE;

  /* Superusers bypass external authorization */
  if (superuser_arg(auth_info->roleid))
    return PG_AUTH_RESULT_IGNORE;

  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return PG_AUTH_RESULT_IGNORE;

  if (cedar_log_decisions) {
      if (rolename && rolename[0] != '\0')
          ereport(LOG, (errmsg("pg_authorization: check role %s (oid %u) for event %d",
                               rolename, auth_info->roleid, auth_info->event_type)));
      else
          ereport(LOG, (errmsg("pg_authorization: check role oid %u for event %d",
                               auth_info->roleid, auth_info->event_type)));
  }

  switch (auth_info->event_type) {
  case PG_AUTH_EVENT_DML:
    required_perms = auth_info->info.dml.required_perms;
    check_perms_loop = true;
    classid = RelationRelationId;
    resource_oid = auth_info->info.dml.relid;
    subid = 0;
    resource_type = "Table";
    break;

  case PG_AUTH_EVENT_DDL:
  case PG_AUTH_EVENT_UTILITY:
    if (auth_info->info.ddl.command_tag) {
        int32 action_key;
        AuthorizationResult cached;

        check_perms_loop = false;
        classid = auth_info->info.ddl.classid;
        resource_oid = auth_info->info.ddl.objectid;
        subid = auth_info->info.ddl.subid;

        if (classid == RelationRelationId)
          resource_type = "Table";
        else if (classid == NamespaceRelationId)
          resource_type = "Schema";
        else if (classid == DatabaseRelationId)
          resource_type = "Database";
        else if (classid == AuthIdRelationId)
          resource_type = "User";
        else if (classid == ProcedureRelationId)
          resource_type = "Routine";
        else
          resource_type = "Object";

        action_key = (int32) hash_any((const unsigned char *) auth_info->info.ddl.command_tag,
                                      (int) strlen(auth_info->info.ddl.command_tag));

        cached = check_auth_cache(auth_info->roleid, classid, resource_oid, subid, action_key);
        if (cached != PG_AUTH_RESULT_IGNORE) {
          result = cached;
          goto cleanup;
        }

        /* Cache miss: resolve rolename and resource_id only now */
        if (rolename == NULL || rolename[0] == '\0')
        {
            HeapTuple roleTup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(auth_info->roleid));
            if (HeapTupleIsValid(roleTup))
            {
                Form_pg_authid roleForm = (Form_pg_authid) GETSTRUCT(roleTup);
                resolved_rolename = pstrdup(NameStr(roleForm->rolname));
                rolename = resolved_rolename;
                have_resolved_rolename = true;
                ReleaseSysCache(roleTup);
            }
            else
            {
                rolename = "unknown";
            }
        }

        if (auth_info->info.ddl.schemaname && auth_info->info.ddl.objectname)
          resource_id_str = psprintf("%s.%s", auth_info->info.ddl.schemaname, auth_info->info.ddl.objectname);
        else if (auth_info->info.ddl.objectname)
          resource_id_str = pstrdup(auth_info->info.ddl.objectname);
        else
          resource_id_str = psprintf("oid_%u", auth_info->info.ddl.objectid);
        have_resource_id = true;

        if (cedar_collect_stats) stats->auth_requests++;
        result = cedar_call_is_authorized_internal(
            "User", rolename,
            auth_info->info.ddl.command_tag,
            resource_type, resource_id_str);

        if (result != PG_AUTH_RESULT_IGNORE)
          update_auth_cache(auth_info->roleid, classid, resource_oid, subid, action_key, result);

        goto cleanup;
    }
    else {
        result = PG_AUTH_RESULT_IGNORE;
        goto cleanup;
    }
    break;

  case PG_AUTH_EVENT_ACL_CHECK:
    {
        required_perms = auth_info->info.ddl.required_perms;
        check_perms_loop = true;
        classid = auth_info->info.ddl.classid;
        resource_oid = auth_info->info.ddl.objectid;
        subid = auth_info->info.ddl.subid;

        if (classid == RelationRelationId)
            resource_type = (subid != 0) ? "Column" : "Table";
        else if (classid == NamespaceRelationId)
            resource_type = "Schema";
        else if (classid == TypeRelationId)
            resource_type = "Type";
        else if (classid == DatabaseRelationId)
            resource_type = "Database";
        else if (classid == ProcedureRelationId)
            resource_type = "Routine";
        else if (classid == AuthIdRelationId)
            resource_type = "User";
        else
            resource_type = "Object";
    }
    break;

  default:
    result = PG_AUTH_RESULT_IGNORE;
    goto cleanup;
  }

  if (check_perms_loop) {
      int i;
      if (required_perms == 0) {
          result = PG_AUTH_RESULT_GRANT;
          goto cleanup;
      }
      result = PG_AUTH_RESULT_DENY;

      for (i = 0; i < 32; i++) {
          AclMode bit = (1 << i);
          if ((required_perms & bit) != 0) {
              int32 action_key = (int32) bit;
              AuthorizationResult cached = check_auth_cache(auth_info->roleid, classid, resource_oid, subid, action_key);
              if (cached != PG_AUTH_RESULT_IGNORE) {
                  if (cached != PG_AUTH_RESULT_GRANT) {
                      result = cached;
                      goto cleanup;
                  }
                  continue;
              }

              /* Cache miss: resolve rolename + resource_id only when needed */
              if (rolename == NULL || rolename[0] == '\0')
              {
                  HeapTuple roleTup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(auth_info->roleid));
                  if (HeapTupleIsValid(roleTup))
                  {
                      Form_pg_authid roleForm = (Form_pg_authid) GETSTRUCT(roleTup);
                      resolved_rolename = pstrdup(NameStr(roleForm->rolname));
                      rolename = resolved_rolename;
                      have_resolved_rolename = true;
                      ReleaseSysCache(roleTup);
                  }
                  else
                  {
                      rolename = "unknown";
                  }
              }

              if (!have_resource_id) {
                  if (auth_info->event_type == PG_AUTH_EVENT_DML) {
                      if (auth_info->info.dml.schemaname && auth_info->info.dml.relname)
                          resource_id_str = psprintf("%s.%s", auth_info->info.dml.schemaname, auth_info->info.dml.relname);
                      else if (auth_info->info.dml.relname)
                          resource_id_str = pstrdup(auth_info->info.dml.relname);
                      else
                          resource_id_str = psprintf("oid_%u", auth_info->info.dml.relid);
                  } else if (classid == RelationRelationId) {
                      char *rel_name = get_rel_name(resource_oid);
                      if (subid != 0) {
                          if (rel_name) {
                              Oid ns_oid = get_rel_namespace(resource_oid);
                              char *sch_name = get_namespace_name(ns_oid);
                              char *col_name = get_attname(resource_oid, subid, false);

                              if (sch_name && col_name)
                                  resource_id_str = psprintf("%s.%s.%s", sch_name, rel_name, col_name);
                              else if (rel_name && col_name)
                                  resource_id_str = psprintf("%s.%s", rel_name, col_name);
                              else
                                  resource_id_str = psprintf("oid_%u.att_%d", resource_oid, subid);

                              if (col_name) pfree(col_name);
                              if (sch_name) pfree(sch_name);
                              pfree(rel_name);
                          } else {
                              resource_id_str = psprintf("oid_%u.att_%d", resource_oid, subid);
                          }
                      } else {
                          if (rel_name) {
                              Oid ns_oid = get_rel_namespace(resource_oid);
                              char *sch_name = get_namespace_name(ns_oid);
                              if (sch_name)
                                  resource_id_str = psprintf("%s.%s", sch_name, rel_name);
                              else
                                  resource_id_str = pstrdup(rel_name);
                              pfree(rel_name);
                              if (sch_name) pfree(sch_name);
                          } else {
                              resource_id_str = psprintf("oid_%u", resource_oid);
                          }
                      }
                  } else if (classid == NamespaceRelationId) {
                      char *nsp_name = get_namespace_name(resource_oid);
                      if (nsp_name) {
                          resource_id_str = pstrdup(nsp_name);
                          pfree(nsp_name);
                      } else {
                          resource_id_str = psprintf("oid_%u", resource_oid);
                      }
                  } else if (classid == TypeRelationId) {
                      char *type_name = format_type_be(resource_oid);
                      if (type_name) {
                          resource_id_str = pstrdup(type_name);
                          pfree(type_name);
                      } else {
                          resource_id_str = psprintf("oid_%u", resource_oid);
                      }
                  } else if (classid == DatabaseRelationId) {
                      char *db_name = get_database_name(resource_oid);
                      if (db_name) {
                          resource_id_str = pstrdup(db_name);
                          pfree(db_name);
                      } else {
                          resource_id_str = psprintf("oid_%u", resource_oid);
                      }
                  } else if (classid == ProcedureRelationId) {
                      char *proc_name = get_func_name(resource_oid);
                      if (proc_name) {
                          resource_id_str = pstrdup(proc_name);
                          pfree(proc_name);
                      } else {
                          resource_id_str = psprintf("oid_%u", resource_oid);
                      }
                  } else {
                      resource_id_str = psprintf("class_%u_oid_%u", classid, resource_oid);
                  }
                  have_resource_id = true;
              }

              {
                  const char *action = get_cedar_action_for_bit(bit);
                  if (action) {
                      if (cedar_collect_stats) stats->auth_requests++;
                      result = cedar_call_is_authorized_internal(
                          "User", rolename,
                          action,
                          resource_type, resource_id_str);
                      if (result != PG_AUTH_RESULT_IGNORE)
                          update_auth_cache(auth_info->roleid, classid, resource_oid, subid, action_key, result);
                      if (result != PG_AUTH_RESULT_GRANT) {
                          goto cleanup;
                      }
                  }
              }
          }
      }
      result = PG_AUTH_RESULT_GRANT;
  }

cleanup:
  if (have_resource_id && resource_id_str) pfree(resource_id_str);
  if (have_resolved_rolename && resolved_rolename) pfree(resolved_rolename);
  return result;
}

/* --------------------------------------------------------------------------
 * Object access hook callback
 * --------------------------------------------------------------------------
 */
static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg) {
  const char *entity_type = NULL;
  char *entity_id = NULL;
  char *schema_name = NULL;

  if (prev_object_access_hook)
    prev_object_access_hook(access, classId, objectId, subId, arg);

  if (!cedar_authorization_enabled && !cedar_entity_sync_enabled)
    return;

  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return;

  if (cedar_entity_sync_enabled) {
    switch (classId) {
    case RelationRelationId:
      {
        char relkind = get_rel_relkind(objectId);
        if (relkind == '\0') {
          Relation rel = relation_open(objectId, NoLock);
          relkind = rel->rd_rel->relkind;
          relation_close(rel, NoLock);
        }
        if (relkind != RELKIND_RELATION && relkind != RELKIND_VIEW &&
            relkind != RELKIND_MATVIEW && relkind != RELKIND_PARTITIONED_TABLE)
          break;

        {
          Oid ns_oid = InvalidOid;
          char *rel_name;
          entity_type = "Table";
          rel_name = get_rel_name(objectId);
          if (rel_name) ns_oid = get_rel_namespace(objectId);
          else {
            Relation rel = relation_open(objectId, NoLock);
            rel_name = pstrdup(RelationGetRelationName(rel));
            ns_oid = RelationGetNamespace(rel);
            relation_close(rel, NoLock);
          }
          if (rel_name) {
            schema_name = get_namespace_name(ns_oid);
            entity_id = schema_name ? psprintf("%s.%s", schema_name, rel_name) : pstrdup(rel_name);
            pfree(rel_name);
          }
        }
      }
      break;

    case NamespaceRelationId:
      {
        HeapTuple tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(tup)) {
          Form_pg_namespace nspForm = (Form_pg_namespace) GETSTRUCT(tup);
          entity_id = pstrdup(NameStr(nspForm->nspname));
          entity_type = "Schema";
          ReleaseSysCache(tup);
        }
      }
      break;

    case AuthIdRelationId:
      entity_type = "User";
      {
        HeapTuple roleTup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(roleTup)) {
          Form_pg_authid roleForm = (Form_pg_authid)GETSTRUCT(roleTup);
          entity_id = pstrdup(NameStr(roleForm->rolname));
          ReleaseSysCache(roleTup);
        }
      }
      break;

    case DatabaseRelationId:
      entity_type = "Database";
      entity_id = get_database_name(objectId);
      break;

    case ProcedureRelationId:
      entity_type = "Routine";
      {
        HeapTuple procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(procTup)) {
          Form_pg_proc procForm = (Form_pg_proc)GETSTRUCT(procTup);
          schema_name = get_namespace_name(procForm->pronamespace);
          entity_id = schema_name ? psprintf("%s.%s", schema_name, NameStr(procForm->proname)) : pstrdup(NameStr(procForm->proname));
          ReleaseSysCache(procTup);
        }
      }
      break;

    default: break;
    }

    if (entity_type && entity_id) {
      switch (access) {
      case OAT_POST_CREATE:
      case OAT_POST_ALTER:
        cedar_sync_entity_upsert(entity_type, entity_id);
        break;
      case OAT_DROP:
        cedar_sync_entity_delete(entity_type, entity_id);
        break;
      default: break;
      }
    }
    if (entity_id && entity_id != schema_name) pfree(entity_id);
    if (schema_name) pfree(schema_name);
  }
}

/* --------------------------------------------------------------------------
 * Process utility hook callback
 * --------------------------------------------------------------------------
 */
static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc) {
  if (prev_process_utility_hook)
    prev_process_utility_hook(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
  else
    standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);

  if (cedar_entity_sync_enabled && cedar_agent_url != NULL && cedar_agent_url[0] != '\0' &&
      pstmt != NULL && pstmt->utilityStmt != NULL) {
    Node *parsetree = (Node *) pstmt->utilityStmt;

    if (IsA(parsetree, CreateRoleStmt)) {
      CreateRoleStmt *stmt = (CreateRoleStmt *) parsetree;
      if (stmt->role && stmt->role[0] != '\0') cedar_sync_entity_upsert("User", stmt->role);
    } else if (IsA(parsetree, CreateSchemaStmt)) {
      CreateSchemaStmt *stmt = (CreateSchemaStmt *) parsetree;
      if (stmt->schemaname && stmt->schemaname[0] != '\0') cedar_sync_entity_upsert("Schema", stmt->schemaname);
    }
  }
}

/* --------------------------------------------------------------------------
 * Authorization Cache Management
 * --------------------------------------------------------------------------
 */
static void reset_auth_cache(void) {
  if (stats == NULL) return;
  stats->last_cache_reset = GetCurrentTimestamp();
}

static AuthorizationResult check_auth_cache(Oid roleid, Oid classid, Oid resource_oid,
                                           int32 subid, int32 action) {
  AuthCacheKey key;
  AuthCacheEntry *entry;
  TimestampTz now = GetCurrentTimestamp();
  AuthorizationResult result = PG_AUTH_RESULT_IGNORE;

  if (!cedar_cache_enabled || auth_cache == NULL || auth_cache_lock == NULL || stats == NULL) return PG_AUTH_RESULT_IGNORE;

  memset(&key, 0, sizeof(key));
  key.roleid = roleid;
  key.classid = classid;
  key.resource_oid = resource_oid;
  key.subid = subid;
  key.action = action;

  LWLockAcquire(auth_cache_lock, LW_SHARED);
  entry = (AuthCacheEntry *) hash_search(auth_cache, &key, HASH_FIND, NULL);
  if (entry != NULL) {
    if (now < entry->expires && entry->created_at >= stats->last_cache_reset) {
      if (cedar_collect_stats) cache_stats->hits++;
      result = entry->result;
    }
  }
  LWLockRelease(auth_cache_lock);

  if (entry != NULL && (now >= entry->expires || entry->created_at < stats->last_cache_reset)) {
    /* Expired or invalidated - try to remove it */
    LWLockAcquire(auth_cache_lock, LW_EXCLUSIVE);
    hash_search(auth_cache, &key, HASH_REMOVE, NULL);
    LWLockRelease(auth_cache_lock);
  }

  if (result == PG_AUTH_RESULT_IGNORE)
  {
    if (cedar_collect_stats) cache_stats->misses++;
  }

  return result;
}

static void update_auth_cache(Oid roleid, Oid classid, Oid resource_oid,
                             int32 subid, int32 action, AuthorizationResult result) {
  AuthCacheKey key;
  AuthCacheEntry *entry;
  bool found;
  TimestampTz now = GetCurrentTimestamp();

  if (!cedar_cache_enabled || auth_cache == NULL || auth_cache_lock == NULL) return;

  memset(&key, 0, sizeof(key));
  key.roleid = roleid;
  key.classid = classid;
  key.resource_oid = resource_oid;
  key.subid = subid;
  key.action = action;

  LWLockAcquire(auth_cache_lock, LW_EXCLUSIVE);
  
  /* 
   * Basic eviction: if cache is full, we must make room.
   * In a shared HTAB with fixed size, HASH_ENTER will fail if we are at cedar_cache_size.
   */
  if (hash_get_num_entries(auth_cache) >= cedar_cache_size) {
    HASH_SEQ_STATUS status;
    AuthCacheEntry *iter_entry;

    if (cedar_collect_stats) cache_stats->evictions++;
    
    /* Soft reset: invalidate all existing entries by updating the global timestamp */
    if (stats) stats->last_cache_reset = now;

    /* Hard reset: physically remove entries to ensure HASH_ENTER succeeds */
    hash_seq_init(&status, auth_cache);
    while ((iter_entry = hash_seq_search(&status)) != NULL)
    {
        hash_search(auth_cache, &iter_entry->key, HASH_REMOVE, NULL);
    }
  }

  entry = (AuthCacheEntry *) hash_search(auth_cache, &key, HASH_ENTER, &found);
  if (entry) {
    entry->result = result;
    entry->created_at = now;
    entry->expires = TimestampTzPlusMilliseconds(now, cedar_cache_ttl * 1000);
  }
  
  LWLockRelease(auth_cache_lock);
}

/* --------------------------------------------------------------------------
 * Module initialization function
 * --------------------------------------------------------------------------
 */
void _PG_init(void) {
  if (!process_shared_preload_libraries_in_progress)
    ereport(ERROR,
            (errmsg("pg_authorization must be loaded via shared_preload_libraries")));

  prev_shmem_request_hook = shmem_request_hook;
  shmem_request_hook = pg_auth_shmem_request;
  prev_shmem_startup_hook = shmem_startup_hook;
  shmem_startup_hook = pg_auth_shmem_startup;

  curl_global_init(CURL_GLOBAL_ALL);

  DefineCustomStringVariable(
      "pg_authorization.cedar_agent_url", "Base URL of the Cedar Agent service",
      NULL, &cedar_agent_url, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomIntVariable("pg_authorization.timeout",
                          "Timeout for Cedar Agent requests in milliseconds",
                          NULL, &cedar_request_timeout, 5000, 100, 60000,
                          PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);

  DefineCustomStringVariable(
      "pg_authorization.namespace", "Namespace for Cedar authorization",
      NULL, &cedar_namespace, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable("pg_authorization.enabled",
                           "Enable Cedar authorization checks", NULL,
                           &cedar_authorization_enabled, true, PGC_SIGHUP, 0,
                           NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.entity_sync_enabled",
      "Enable entity synchronization to Cedar Agent", NULL,
      &cedar_entity_sync_enabled, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.log_decisions",
      "Log authorization decisions", NULL,
      &cedar_log_decisions, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.collect_stats",
      "Collect authorization statistics in shared memory", NULL,
      &cedar_collect_stats, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  /* Cache GUCs */
  DefineCustomBoolVariable(
      "pg_authorization.cache_enabled", "Enable authorization caching", NULL,
      &cedar_cache_enabled, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pg_authorization.cache_size", "Maximum number of entries in auth cache", NULL,
      &cedar_cache_size, 1024, 64, 100000, PGC_POSTMASTER, 0, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pg_authorization.cache_ttl", "TTL for cache entries in seconds", NULL,
      &cedar_cache_ttl, 300, 1, 86400, PGC_SIGHUP, GUC_UNIT_S, NULL, NULL, NULL);

  /* HTTPS/SSL GUCs */
  DefineCustomBoolVariable(
      "pg_authorization.use_https", "Enable HTTPS for Cedar Agent communication", NULL,
      &cedar_use_https, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.ssl_verify_peer", "Enable SSL certificate verification", NULL,
      &cedar_ssl_verify_peer, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomStringVariable(
      "pg_authorization.ssl_cert_file", "Path to client certificate file for mTLS", NULL,
      &cedar_ssl_cert_file, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomStringVariable(
      "pg_authorization.ssl_key_file", "Path to client private key file for mTLS", NULL,
      &cedar_ssl_key_file, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  MarkGUCPrefixReserved("pg_authorization");

  prev_object_access_hook = object_access_hook;
  object_access_hook = cedar_object_access_hook;

  prev_process_utility_hook = ProcessUtility_hook;
  ProcessUtility_hook = cedar_process_utility_hook;

  prev_universal_auth_hook = universal_authorization_hook;
  universal_authorization_hook = cedar_authorization_hook;

  ereport(LOG, (errmsg("pg_authorization: extension loaded")));
}

void _PG_fini(void) {
  if (persistent_curl) {
    curl_easy_cleanup(persistent_curl);
    persistent_curl = NULL;
  }
  curl_global_cleanup();
}

/* --------------------------------------------------------------------------
 * SQL Functions
 * --------------------------------------------------------------------------
 */
Datum pg_authorization_is_enabled(PG_FUNCTION_ARGS) { PG_RETURN_BOOL(cedar_authorization_enabled); }

Datum pg_authorization_stats(PG_FUNCTION_ARGS) {
  TupleDesc tupdesc = CreateTemplateTupleDesc(10);
  Datum values[10];
  bool nulls[10] = {false};
  TupleDescInitEntry(tupdesc, 1, "auth_requests", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 2, "auth_grants", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 3, "auth_denies", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 4, "auth_ignores", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 5, "auth_errors", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 6, "sync_requests", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 7, "sync_successes", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 8, "sync_failures", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 9, "avg_total_time_ms", FLOAT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 10, "avg_remote_time_ms", FLOAT8OID, -1, 0);
  tupdesc = BlessTupleDesc(tupdesc);
  values[0] = Int64GetDatum(stats->auth_requests);
  values[1] = Int64GetDatum(stats->auth_grants);
  values[2] = Int64GetDatum(stats->auth_denies);
  values[3] = Int64GetDatum(stats->auth_ignores);
  values[4] = Int64GetDatum(stats->auth_errors);
  values[5] = Int64GetDatum(stats->sync_requests);
  values[6] = Int64GetDatum(stats->sync_successes);
  values[7] = Int64GetDatum(stats->sync_failures);
  
  if (stats->auth_requests > 0) {
    values[8] = Float8GetDatum((stats->auth_total_time * 1000.0) / stats->auth_requests);
    values[9] = Float8GetDatum((stats->auth_remote_time * 1000.0) / stats->auth_requests);
  } else {
    values[8] = Float8GetDatum(0.0);
    values[9] = Float8GetDatum(0.0);
  }
  
  PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

Datum pg_authorization_reset_stats(PG_FUNCTION_ARGS) {
  stats->auth_requests = stats->auth_grants = stats->auth_denies = stats->auth_ignores = stats->auth_errors = 0;
  stats->auth_total_time = stats->auth_remote_time = 0;
  stats->sync_requests = stats->sync_successes = stats->sync_failures = 0;
  PG_RETURN_VOID();
}

Datum pg_authorization_sync_entity(PG_FUNCTION_ARGS) {
  char *type = text_to_cstring(PG_GETARG_TEXT_PP(0));
  char *id = text_to_cstring(PG_GETARG_TEXT_PP(1));
  bool res = cedar_sync_entity_upsert(type, id);
  pfree(type); pfree(id);
  PG_RETURN_BOOL(res);
}

Datum pg_authorization_cache_stats(PG_FUNCTION_ARGS) {
  TupleDesc tupdesc = CreateTemplateTupleDesc(4);
  Datum values[4];
  bool nulls[4] = {false};
  TupleDescInitEntry(tupdesc, 1, "hits", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 2, "misses", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 3, "evictions", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 4, "entries", INT8OID, -1, 0);
  tupdesc = BlessTupleDesc(tupdesc);
  values[0] = Int64GetDatum(cache_stats->hits);
  values[1] = Int64GetDatum(cache_stats->misses);
  values[2] = Int64GetDatum(cache_stats->evictions);
  values[3] = Int64GetDatum(auth_cache ? hash_get_num_entries(auth_cache) : 0);
  PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

Datum pg_authorization_cache_reset(PG_FUNCTION_ARGS) {
  reset_auth_cache();
  cache_stats->hits = cache_stats->misses = cache_stats->evictions = 0;
  PG_RETURN_VOID();
}

Datum pg_authorization_flush_syscache(PG_FUNCTION_ARGS) {
  InvalidateSystemCaches();
  PG_RETURN_VOID();
}
