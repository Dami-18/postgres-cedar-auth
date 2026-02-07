# contrib/pg_authorization/Makefile

MODULE_big = pg_authorization
OBJS = \
	$(WIN32RES) \
	pg_authorization.o

# libcurl dependency
PG_CPPFLAGS = $(shell pkg-config --cflags libcurl 2>/dev/null)
SHLIB_LINK = $(shell pkg-config --libs libcurl 2>/dev/null)

EXTENSION = pg_authorization
DATA = pg_authorization--1.0.sql
PGFILEDESC = "pg_authorization - external authorization plugin for PostgreSQL"

REGRESS = pg_authorization
TAP_TESTS = 1

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_authorization
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

