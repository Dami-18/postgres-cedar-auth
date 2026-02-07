#!/bin/bash
# Troubleshooting script for Docker build issues

echo "🔍 Docker Build Troubleshooting"
echo "================================"

# Check Docker status
echo ""
echo "1. Docker System Info:"
docker system info | head -20

echo ""
echo "2. Docker Version:"
docker --version

echo ""
echo "3. Available Disk Space:"
df -h /var/lib/docker 2>/dev/null || df -h | head -5

echo ""
echo "4. Build Cache Status:"
docker system df

echo ""
echo "5. Test basic Docker functionality:"
if docker run --rm hello-world &>/dev/null; then
    echo "✓ Docker basic functionality works"
else
    echo "✗ Docker basic functionality failed"
fi

echo ""
echo "6. Test Ubuntu base image:"
if docker pull ubuntu:22.04 &>/dev/null; then
    echo "✓ Ubuntu base image accessible"
else
    echo "✗ Ubuntu base image failed"
fi

echo ""
echo "🔧 Common Issues Fixed:"
echo "========================"
echo "✓ UUID library dependency added (fixes 'library uuid is required for E2FS UUID')"
echo "✓ DEBIAN_FRONTEND=noninteractive (prevents interactive prompts)"
echo "✓ .dockerignore created (reduces build context size)"
echo ""
echo "📋 Troubleshooting Commands:"
echo "=============================="
echo ""
echo "# Clean Docker cache if needed:"
echo "docker system prune -f"
echo ""
echo "# Check running containers:"
echo "docker ps"
echo ""
echo "# Monitor build in real-time:"
echo "docker stats"
echo ""
echo "# Alternative build with no cache:"
echo "docker build --no-cache -f postgres-cedar.Dockerfile -t test-build ."
echo ""
echo "# Build with more memory (if using Docker Desktop):"
echo "# Increase memory allocation in Docker Desktop settings"
