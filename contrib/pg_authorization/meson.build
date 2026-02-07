# Copyright (c) 2024, PostgreSQL Global Development Group

# pg_authorization requires libcurl for external authorization service support
curl_dep = dependency('libcurl', required: false)

if not curl_dep.found()
  subdir_done()
endif

pg_authorization_sources = files(
  'pg_authorization.c',
)

if host_system == 'windows'
  pg_authorization_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'pg_authorization',
    '--FILEDESC', 'pg_authorization - external authorization plugin for PostgreSQL',])
endif

pg_authorization = shared_module('pg_authorization',
  pg_authorization_sources,
  kwargs: contrib_mod_args + {
    'dependencies': [curl_dep, contrib_mod_args['dependencies']],
  },
)
contrib_targets += pg_authorization

install_data(
  'pg_authorization.control',
  'pg_authorization--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'pg_authorization',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'pg_authorization',
    ],
  },
  'tap': {
    'tests': [
      't/001_basic.pl',
    ],
  },
}

