# PostgreSQL Docker Images for Cedar Authorization Benchmarking

This directory contains Dockerfiles and configuration for building PostgreSQL images used in the Cedar authorization benchmarking framework.

## Images

### Baseline PostgreSQL
- **Purpose**: Baseline PostgreSQL without authorization hooks
- **Image**: `postgres:17.7` (standard)
- **Use**: Compare performance against standard PostgreSQL
- **Note**: No custom Dockerfile needed - uses official PostgreSQL image

### `postgres-cedar.Dockerfile`
- **Purpose**: Modified PostgreSQL with universal authorization hooks
- **Base**: Custom build from modified PostgreSQL source
- **Use**: Test Cedar authorization integration

## Building Images

### Prerequisites
- Modified PostgreSQL source code with Cedar hooks (this directory)
- Docker with buildx support

### Build Commands

#### Option 1: Use the automated build script (recommended)
```bash
# Set your registry and run the build script
export REGISTRY=your-registry.com
export TAG=latest
./build_and_push.sh
```

**Build script options:**
- `REGISTRY`: Your Docker registry (default: `your-registry.com`)
- `IMAGE_NAME`: Image name (default: `postgres-cedar`)
- `TAG`: Image tag (default: `latest`)
- `SKIP_TEST`: Set to `true` to skip image testing (default: `false`)

### Troubleshooting

If the build fails or hangs:
```bash
# Run diagnostics
./troubleshoot_build.sh

# Clean cache and retry
docker system prune -f
./build_and_push.sh

# Build without cache (slower but fresh)
docker build --no-cache -f postgres-cedar.Dockerfile -t your-image .
```

#### Option 2: Manual build commands
```bash
# Baseline PostgreSQL: Use official image (no build needed)
# docker pull postgres:17.7

# Build Cedar PostgreSQL image manually
docker build -f postgres-cedar.Dockerfile -t your-registry.com/postgres-cedar:latest .
docker push your-registry.com/postgres-cedar:latest
```

## Configuration Files

- `postgres-init.sql`: Database initialization script with test schema
- `cedar_auth.control`: PostgreSQL extension control file
- `cedar_auth--1.0.sql`: Cedar authorization extension SQL

## Using in Experiments

After building and pushing the image using `./build_and_push.sh`, set the environment variable:

```bash
export POSTGRES_CEDAR_IMAGE=your-registry.com/postgres-cedar:latest
```

Then start the services:

```bash
docker-compose up postgres-baseline postgres-cedar -d
```

Note: The baseline service uses the official `postgres:17.7` image directly, so no environment variable is needed for it.

## Testing

Run the integration tests:

```bash
cd /path/to/experiments
python test_postgres_integration.py
```

## Benchmarking

Use the pgbench commands:

```bash
# Run on baseline
make e8-pgbench-baseline

# Run on Cedar
make e8-pgbench-cedar

# Compare both
make e8-pgbench-compare
```

## Architecture Notes

The Cedar PostgreSQL image builds from the modified source in this directory, which includes:

- Universal authorization hooks (`pg_aclmask_ext`, `object_access_hook`, `ProcessUtility_hook`)
- DDL entity sync hooks for metadata management
- Cedar extension for policy agent integration

The baseline image uses standard PostgreSQL 16 for performance comparison.
