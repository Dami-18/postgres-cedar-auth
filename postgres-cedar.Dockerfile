# Modified PostgreSQL with Cedar authorization hooks
# Builds from the modified PostgreSQL source with universal authorization hooks

# Use the same base for the builder to ensure library compatibility
FROM postgres:17.7 AS builder

# Install build dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    libreadline-dev \
    zlib1g-dev \
    flex \
    bison \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
    libpam0g-dev \
    libedit-dev \
    libkrb5-dev \
    libldap2-dev \
    libcurl4-openssl-dev \
    libselinux1-dev \
    libnss-wrapper \
    gettext \
    python3-dev \
    tcl-dev \
    perl \
    pkg-config \
    uuid-dev \
    libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /postgres-build

# Copy the modified PostgreSQL source
COPY . /postgres-build/

# Configure and build PostgreSQL
# We use --with-uuid=e2fs which requires uuid-dev
# Optimized build for production performance
RUN ./configure \
    --prefix=/usr/local/pgsql \
    --with-openssl \
    --with-libxml \
    --with-libxslt \
    --with-uuid=e2fs \
    --enable-depend \
    CFLAGS="-O2 -march=native -mtune=native" \
    && make -j$(nproc) \
    && make -j$(nproc) -C contrib \
    && make install \
    && make -C contrib install

# Final stage: Use the official PostgreSQL 17.7 image as base
# This provides the entrypoint, default configuration, and standard environment
FROM postgres:17.7

# Install additional runtime dependencies that might not be in the base image
# CRITICAL: libcurl4 is required for the pg_authorization extension
RUN apt-get update && apt-get install -y \
    libxslt1.1 \
    libselinux1 \
    libuuid1 \
    libxml2 \
    libcurl4 \
    libicu76 \
    && rm -rf /var/lib/apt/lists/*

# Copy our built PostgreSQL over the existing one or to a separate prefix
# We'll put it in /usr/local/pgsql as before, but ensure it's used
COPY --from=builder /usr/local/pgsql /usr/local/pgsql

# Prepend our build to PATH so the entrypoint and users use our modified version
ENV PATH=/usr/local/pgsql/bin:$PATH
ENV PGDATA=/var/lib/postgresql/data

# Ensure the postgres user owns the new files
RUN chown -R postgres:postgres /usr/local/pgsql

# Update shared library cache and ensure our lib directory is searched
RUN echo "/usr/local/pgsql/lib" > /etc/ld.so.conf.d/00-postgres-custom.conf && ldconfig

# Also symlink our built PostgreSQL components to the official locations.
# This ensures that the official image's entrypoint and scripts find our modified
# versions instead of the standard ones.
RUN mkdir -p /usr/lib/postgresql/17/lib/ && \
    ln -sf /usr/local/pgsql/lib/pg_authorization.so /usr/lib/postgresql/17/lib/pg_authorization.so && \
    mkdir -p /usr/share/postgresql/17/extension/ && \
    ln -sf /usr/local/pgsql/share/extension/pg_authorization* /usr/share/postgresql/17/extension/ && \
    ln -sf /usr/local/pgsql/bin/postgres /usr/lib/postgresql/17/bin/postgres && \
    ln -sf /usr/local/pgsql/bin/pg_config /usr/lib/postgresql/17/bin/pg_config

# Copy initialization scripts (official image entrypoint uses this directory)
COPY postgres-init.sql /docker-entrypoint-initdb.d/

# Note: The official image already has EXPOSE 5432, ENTRYPOINT, and CMD
