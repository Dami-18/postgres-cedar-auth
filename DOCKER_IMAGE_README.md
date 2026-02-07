# PostgreSQL with Cedar Authorization Extension

This Docker image contains PostgreSQL with a custom authorization extension that integrates with AWS Cedar for fine-grained access control.

## Image Details

- **Base**: PostgreSQL (latest stable)
- **Architecture**: Multi-platform (amd64, arm64)
- **Extension**: `pg_authorization` - Cedar-based authorization

## Features

- Cedar policy-based authorization for database operations
- Query-level access control
- Integration with Cedar policy decision point (cedar-agent)
- Configurable authorization logging
- Statistics and caching support

## Usage

```bash
docker pull ghcr.io/archarcade/postgres-cedar:latest

docker run -d \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=mydb \
  -p 5432:5432 \
  ghcr.io/archarcade/postgres-cedar:latest \
  -c shared_preload_libraries=pg_authorization \
  -c pg_authorization.enabled=on \
  -c pg_authorization.cedar_agent_url=http://cedar-agent:8180
```

## Configuration

Key PostgreSQL parameters:
- `pg_authorization.enabled` - Enable/disable authorization (on/off)
- `pg_authorization.cedar_agent_url` - Cedar agent endpoint
- `pg_authorization.namespace` - Authorization namespace
- `pg_authorization.log_decisions` - Log authorization decisions

## Related

- Cedar Agent: `ghcr.io/archarcade/cedar-agent`
- Research: See accompanying research paper
