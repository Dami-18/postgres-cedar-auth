#!/bin/bash
# Build and push multi-arch Cedar PostgreSQL Docker image
# This script builds the modified PostgreSQL with Cedar authorization hooks for multiple architectures

set -e  # Exit on any error

# Configuration
REGISTRY="${REGISTRY:-ghcr.io/archarcade}"
IMAGE_NAME="${IMAGE_NAME:-postgres-cedar}"
TAG="${TAG:-latest}"
FULL_IMAGE_NAME="${REGISTRY}/${IMAGE_NAME}:${TAG}"

echo "Building and pushing Cedar PostgreSQL Docker image"
echo "=================================================="
echo "Registry: ${REGISTRY}"
echo "Image: ${IMAGE_NAME}"
echo "Tag: ${TAG}"
echo "Full image: ${FULL_IMAGE_NAME}"
echo ""

# Check if we're in the right directory
if [ ! -f "postgres-cedar.Dockerfile" ]; then
    echo "Error: postgres-cedar.Dockerfile not found in current directory"
    echo "Please run this script from the postgres directory"
    exit 1
fi

# Check if required files exist
REQUIRED_FILES=(
    "postgres-cedar.Dockerfile"
    "postgres-init.sql"
    "contrib/pg_authorization/pg_authorization.control"
    "contrib/pg_authorization/pg_authorization--1.0.sql"
)

echo "Checking required files..."
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file '$file' not found"
        exit 1
    else
        echo "✓ Found $file"
    fi
done
echo ""

# Set up buildx for multi-platform builds
echo "Setting up buildx for multi-platform builds..."
docker buildx use multiarch-postgres || docker buildx create --name multiarch-postgres --use --bootstrap

# Build and push multi-arch Docker image
echo "Building and pushing multi-arch Docker image..."
echo "Platforms: linux/amd64, linux/arm64"
echo "Command: docker buildx build --platform linux/amd64,linux/arm64 --push -f postgres-cedar.Dockerfile -t ${FULL_IMAGE_NAME} ."
echo "Note: This multi-arch build can take 20-30 minutes. It builds for both AMD64 and ARM64 architectures."
echo "Tip: Using buildx for faster multi-platform builds with BuildKit."
docker buildx build --platform linux/amd64,linux/arm64 --push -f postgres-cedar.Dockerfile -t "${FULL_IMAGE_NAME}" .

if [ $? -eq 0 ]; then
    echo "✓ Multi-arch Docker image built and pushed successfully: ${FULL_IMAGE_NAME}"
    echo "  Platforms: linux/amd64, linux/arm64"
else
    echo "✗ Multi-arch Docker build failed"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "Run './troubleshoot_build.sh' for diagnostics"
    echo "Or try: docker buildx prune -f && ./build_and_push.sh"
    echo "Or check buildx setup: docker buildx ls"
    exit 1
fi
echo ""

# Test the image (optional)
if [ "${SKIP_TEST:-false}" != "true" ]; then
    echo "Testing Docker image..."
    if docker run --rm "${FULL_IMAGE_NAME}" --version &>/dev/null; then
        echo "✓ Docker image test passed"
    else
        echo "⚠️  Docker image test failed, but continuing with push"
    fi
    echo ""
fi

# Note: Push is handled by buildx build --push above

# Success message
echo "🎉 Multi-arch build and push completed successfully!"
echo "The image ${FULL_IMAGE_NAME} now supports both AMD64 and ARM64 architectures."
echo ""
echo "Next steps:"
echo "1. Set the environment variable in your experiments:"
echo "   export POSTGRES_CEDAR_IMAGE=${FULL_IMAGE_NAME}"
echo ""
echo "2. Start the PostgreSQL services:"
echo "   cd /path/to/experiments"
echo "   docker-compose up postgres-baseline postgres-cedar -d"
echo ""
echo "3. Run benchmarks:"
echo "   make e8-pgbench-baseline"
echo "   make e8-pgbench-cedar"
echo "   make e8-pgbench-compare"
