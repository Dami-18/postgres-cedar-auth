/*-------------------------------------------------------------------------
 *
 * authorization_hook.h
 *	  Declarations for universal authorization hook infrastructure.
 *
 * This header provides a universal authorization hook that allows extensions
 * to intercept and control authorization decisions at various points in
 * PostgreSQL's permission checking system.
 *
 * The hook is designed to be called from:
 * - DML permission checks (SELECT, INSERT, UPDATE, DELETE)
 * - DDL operations (CREATE, ALTER, DROP)
 * - Utility commands (VACUUM, ANALYZE, etc.)
 * - Object access checks (schemas, functions, etc.)
 *
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/utils/authorization_hook.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef AUTHORIZATION_HOOK_H
#define AUTHORIZATION_HOOK_H

#include "nodes/bitmapset.h"
#include "nodes/parsenodes.h"
#include "utils/acl.h"

/*
 * Authorization event types that trigger the universal authorization hook.
 */
typedef enum AuthorizationEventType
{
	PG_AUTH_EVENT_DML,				/* DML operations (SELECT/INSERT/UPDATE/DELETE) */
	PG_AUTH_EVENT_DDL,				/* DDL operations (CREATE/ALTER/DROP) */
	PG_AUTH_EVENT_UTILITY,			/* Utility commands (VACUUM, ANALYZE, etc.) */
	PG_AUTH_EVENT_OBJECT_ACCESS,	/* Object access (schema search, function exec) */
	PG_AUTH_EVENT_ROLE_CHECK,		/* Role-based checks (SET ROLE, role membership) */
	PG_AUTH_EVENT_ACL_CHECK			/* Direct ACL checks */
} AuthorizationEventType;

/*
 * Result of an authorization decision.
 */
typedef enum AuthorizationResult
{
	PG_AUTH_RESULT_GRANT,		/* Explicitly grant access */
	PG_AUTH_RESULT_DENY,		/* Explicitly deny access */
	PG_AUTH_RESULT_IGNORE		/* Defer to PostgreSQL's native checks */
} AuthorizationResult;

/*
 * Information about an authorization request for DML operations.
 */
typedef struct PgAuthDMLInfo
{
	Oid			relid;			/* Relation OID */
	const char *relname;		/* Relation name (may be NULL) */
	const char *schemaname;		/* Schema name (may be NULL) */
	AclMode		required_perms;	/* Required permissions (ACL bits) */
	Bitmapset  *selected_cols;	/* Columns being selected */
	Bitmapset  *inserted_cols;	/* Columns being inserted */
	Bitmapset  *updated_cols;	/* Columns being updated */
} PgAuthDMLInfo;

/*
 * Information about an authorization request for DDL/Utility operations.
 */
typedef struct PgAuthDDLInfo
{
	Oid			classid;		/* Object class OID (pg_class, pg_proc, etc.) */
	Oid			objectid;		/* Object OID (InvalidOid if not yet created) */
	const char *objectname;		/* Object name (may be NULL) */
	const char *schemaname;		/* Schema name (may be NULL) */
	Node	   *parse_tree;		/* Parse tree for the command */
	const char *command_tag;	/* Command tag (e.g., "CREATE TABLE") */
	int			subid;			/* Sub-object ID (e.g., column number) */
	bool		is_internal;	/* Is this an internal operation? */
	AclMode		required_perms; /* Required permissions (for ACL checks) */
} PgAuthDDLInfo;

/*
 * Main authorization information structure.
 */
typedef struct AuthorizationInfo
{
	AuthorizationEventType event_type;	/* Type of authorization event */

	/* User/role information */
	Oid			roleid;			/* Role OID making the request */
	const char *rolename;		/* Role name (may be NULL) */

	/* Database information */
	Oid			dboid;			/* Database OID */
	const char *dbname;			/* Database name (may be NULL) */

	/* Query information */
	const char *query_string;	/* Original query string (may be NULL) */

	/* Event-specific information */
	union
	{
		PgAuthDMLInfo dml;		/* For PG_AUTH_EVENT_DML */
		PgAuthDDLInfo ddl;		/* For PG_AUTH_EVENT_DDL and PG_AUTH_EVENT_UTILITY */
	}			info;

} AuthorizationInfo;

/*
 * Universal authorization hook type.
 *
 * The hook receives an AuthorizationInfo structure describing the authorization
 * request and should return an AuthorizationResult indicating the decision.
 *
 * PG_AUTH_RESULT_GRANT:  Explicitly grant access (bypass native checks)
 * PG_AUTH_RESULT_DENY:   Explicitly deny access (regardless of native checks)
 * PG_AUTH_RESULT_IGNORE: Let PostgreSQL's native authorization proceed
 *
 * If the hook is NULL or returns PG_AUTH_RESULT_IGNORE, PostgreSQL's native
 * authorization system will handle the request.
 */
typedef AuthorizationResult (*universal_authorization_hook_type) (
	AuthorizationInfo *auth_info);

/* The universal authorization hook variable */
extern PGDLLIMPORT universal_authorization_hook_type universal_authorization_hook;

/*
 * Helper functions for authorization
 */

/* Initialize an AuthorizationInfo structure */
extern void InitAuthorizationInfo(AuthorizationInfo *info,
								  AuthorizationEventType event_type,
								  Oid roleid);

/* Free resources in an AuthorizationInfo structure */
extern void FreeAuthorizationInfo(AuthorizationInfo *info);

/* Get human-readable names for enum values */
extern const char *GetAuthorizationEventTypeName(AuthorizationEventType event_type);
extern const char *GetAuthorizationResultName(AuthorizationResult result);

/* Convert AclMode to human-readable privilege names */
extern char *AclModeToPrivilegeString(AclMode mode);

#endif							/* AUTHORIZATION_HOOK_H */

