# Reproduces the findings of the Lean model (verification/README.md, "Findings")
# against a real server. Each test asserts the behaviour the model predicts,
# next to a control showing the normal behaviour.
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use IO::Socket::INET;
use IPC::Run;
use JSON::PP;

# --- Mock Cedar agent ---------------------------------------------------------
my $sock = IO::Socket::INET->new(Listen => 5, LocalAddr => '127.0.0.1', Proto => 'tcp');
die "Cannot find free port: $!" unless $sock;
my $port = $sock->sockport;
$sock->close;

my $mock_pid = fork();
if ($mock_pid == 0)
{
	exec("python3", "-u", "t/mock_cedar.py", "--port", $port);
	exit 1;
}
my $retries = 20;
while ($retries-- > 0)
{
	last if system("curl -s http://localhost:$port/health > /dev/null") == 0;
	sleep 1;
}

sub mock_mode
{
	my ($name, $arg) = @_;
	my $body = encode_json({ mode => $name, arg => $arg });
	system("curl -s -X POST -H 'Content-Type: application/json' -d '$body' "
		  . "http://localhost:$port/test/mode > /dev/null");
}

sub mock_clear
{
	system("curl -s -X POST http://localhost:$port/test/clear > /dev/null");
}

sub mock_requests
{
	return decode_json(scalar qx(curl -s http://localhost:$port/test/requests));
}

# Authorization requests received since the last clear
sub authz_requests
{
	return grep { exists $_->{principal} } @{ mock_requests() };
}

# --- Cluster ----------------------------------------------------------------
my $node = PostgreSQL::Test::Cluster->new('findings');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_authorization'");
$node->append_conf('postgresql.conf', "listen_addresses = '*'");
$node->append_conf('pg_hba.conf', "host all all 0.0.0.0/0 trust");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_authorization');

sub set_agent_url
{
	my ($url) = @_;
	$node->safe_psql('postgres', "ALTER SYSTEM SET pg_authorization.cedar_agent_url = '$url'");
	$node->safe_psql('postgres', 'SELECT pg_reload_conf()');
	# wait until new sessions see the value
	for (1 .. 50)
	{
		last if $node->safe_psql('postgres', 'SHOW pg_authorization.cedar_agent_url') eq $url;
		select(undef, undef, undef, 0.1);
	}
}
set_agent_url("http://localhost:$port");

sub reset_cache
{
	$node->safe_psql('postgres', 'SELECT pg_authorization_cache_reset()');
}

# Run SQL as a role over the Unix socket; returns (exit code, stdout, stderr)
sub as_role
{
	my ($role, $sql) = @_;
	return $node->psql('postgres', $sql, extra_params => [ '-U', $role ]);
}

# Run SQL as a role over TCP to the given address
my $psql = $node->installed_command('psql');
sub as_role_tcp
{
	my ($role, $host, $sql) = @_;
	my ($out, $err) = ('', '');
	my $connstr = "host=$host port=" . $node->port . " dbname=postgres user=$role";
	my $ok = IPC::Run::run([ $psql, '-XAtq', '-d', $connstr, '-c', $sql ],
		'>', \$out, '2>', \$err);
	return ($ok ? 0 : 1, $out, $err);
}

$node->safe_psql('postgres', 'CREATE ROLE alice LOGIN');
$node->safe_psql('postgres', 'CREATE ROLE bob LOGIN');

my ($ret, $out, $err);

# --- Finding 1: grant-option checks pass for everyone ------------------------
# Model: grant_option_reported_for_everyone, cedarHook_high_bits_granted
$node->safe_psql('postgres', 'CREATE TABLE public.t_go (id int)');
$node->safe_psql('postgres', 'REVOKE ALL ON public.t_go FROM PUBLIC');
mock_mode('deny_all');
reset_cache();

is($node->safe_psql('postgres', "SELECT has_table_privilege('bob', 'public.t_go', 'SELECT')"),
	'f', 'F1 control: Cedar denies bob SELECT');

mock_clear();
is($node->safe_psql('postgres',
		"SELECT has_table_privilege('bob', 'public.t_go', 'SELECT WITH GRANT OPTION')"),
	't', 'F1: bob reported to have SELECT WITH GRANT OPTION although Cedar denies everything');
is(scalar(authz_requests()), 0, 'F1: Cedar was not asked');

set_agent_url('http://localhost:1');    # nothing listens there
reset_cache();
is($node->safe_psql('postgres',
		"SELECT has_table_privilege('bob', 'public.t_go', 'SELECT WITH GRANT OPTION')"),
	't', 'F1: same result with the Cedar agent unreachable');
set_agent_url("http://localhost:$port");

# --- Finding 2: column-level policies are not consulted ----------------------
# Model: pgAttribute_no_acl_never_asks
$node->safe_psql('postgres', 'CREATE TABLE public.t_cols (a int, b int)');
$node->safe_psql('postgres', 'REVOKE ALL ON public.t_cols FROM PUBLIC');
mock_mode('table_deny_column_allow');
reset_cache();
mock_clear();

($ret, $out, $err) = as_role('alice', 'SELECT a FROM public.t_cols');
isnt($ret, 0, 'F2: SELECT a denied although Cedar allows column a');
ok(!(grep { $_->{resource} =~ /^Column::/ } authz_requests()),
	'F2: Cedar was never asked about the column');

# Control: once column a has any column-level GRANT (to someone else), the
# column ACL is non-NULL and Cedar is consulted for it.
$node->safe_psql('postgres', 'GRANT SELECT (a) ON public.t_cols TO bob');
reset_cache();
mock_clear();
($ret, $out, $err) = as_role('alice', 'SELECT a FROM public.t_cols');
is($ret, 0, 'F2 control: with a column ACL present, Cedar allows column a');
ok((grep { $_->{resource} =~ /^Column::/ } authz_requests()),
	'F2 control: Cedar was asked about the column');

# --- Finding 3: "Allow" anywhere in a Deny response grants -------------------
# Model: mapHttp_deny_with_allow_policy_id
$node->safe_psql('postgres', 'CREATE TABLE public.t_parse (id int)');
$node->safe_psql('postgres', 'REVOKE ALL ON public.t_parse FROM PUBLIC');
mock_mode('deny_all');
reset_cache();
($ret, $out, $err) = as_role('alice', 'SELECT * FROM public.t_parse');
isnt($ret, 0, 'F3 control: a plain Deny is denied');

mock_mode('deny_with_allow_reason');
reset_cache();
($ret, $out, $err) = as_role('alice', 'SELECT * FROM public.t_parse');
is($ret, 0, 'F3: a Deny whose diagnostics name a policy "Allow" is treated as Allow');

# --- Finding 4: the cache ignores the client IP ------------------------------
# Model: ContextCache.second_granted_from_cache
my ($tcp_ip) = split(' ', `hostname -I`);
$node->safe_psql('postgres', 'CREATE TABLE public.t_ip (id int)');
$node->safe_psql('postgres', 'REVOKE ALL ON public.t_ip FROM PUBLIC');
mock_mode('allow_ip', '127.0.0.1');    # Unix-socket clients are reported as 127.0.0.1
reset_cache();

($ret, $out, $err) = as_role_tcp('alice', $tcp_ip, 'SELECT * FROM public.t_ip');
isnt($ret, 0, "F4 control: from $tcp_ip with an empty cache, Cedar denies");

reset_cache();
($ret, $out, $err) = as_role('alice', 'SELECT * FROM public.t_ip');
is($ret, 0, 'F4: from 127.0.0.1, Cedar allows (and the answer is cached)');
mock_clear();
($ret, $out, $err) = as_role_tcp('alice', $tcp_ip, 'SELECT * FROM public.t_ip');
is($ret, 0, "F4: from $tcp_ip, allowed from the cache");
is(scalar(authz_requests()), 0, 'F4: Cedar was not asked for the second address');

# --- Finding 5: an answer in flight during a policy change is cached as fresh --
# Model: Race.stale_grant_served
$node->safe_psql('postgres', 'CREATE TABLE public.t_race (id int)');
$node->safe_psql('postgres', 'REVOKE ALL ON public.t_race FROM PUBLIC');
mock_mode('slow_allow', 2);    # answers Allow after 2 s
reset_cache();

my ($bout, $berr) = ('', '');
my $bg = IPC::Run::start(
	[ $psql, '-XAtq', '-d', $node->connstr('postgres') . ' user=alice',
	  '-c', 'SELECT count(*) FROM public.t_race' ],
	'>', \$bout, '2>', \$berr);
sleep 1;                       # the request is now waiting at the agent
mock_mode('deny_all');         # the policy changes ...
reset_cache();                 # ... and the agent invalidates the cache
my $bg_ok = $bg->finish;
ok($bg_ok, 'F5: the in-flight query completes with the old Allow');

mock_clear();
($ret, $out, $err) = as_role('alice', 'SELECT * FROM public.t_race');
is($ret, 0, 'F5: after the reset, the old Allow is still served from the cache');
is(scalar(authz_requests()), 0, 'F5: Cedar was not asked');

reset_cache();
($ret, $out, $err) = as_role('alice', 'SELECT * FROM public.t_race');
isnt($ret, 0, 'F5 control: after another reset, the new policy denies');

# --- Finding 6: a rename re-syncs the old name, never the new one ------------
# Model: Sync.rename_resyncs_old_name (the hook runs before the rename is visible)
$node->safe_psql('postgres', 'CREATE TABLE public.t_old (id int)');
$node->safe_psql('postgres', 'ALTER TABLE public.t_old RENAME TO t_new');
my $entities = qx(curl -s http://localhost:$port/test/entities);
like($entities, qr/public\.t_old/, 'F6: the old table name is still an entity at the agent');
unlike($entities, qr/public\.t_new/, 'F6: the new table name was never synced');

# --- Finding 7: CREATE ROLE is synced only by the utility hook ---------------
# Model: Sync.create_role_synced_once (the new role is not yet visible to the
# object-access hook's syscache lookup)
mock_clear();
$node->safe_psql('postgres', 'CREATE ROLE carol');
my @puts = grep { ($_->{method} // '') eq 'PUT' && $_->{entity} =~ /carol/ } @{ mock_requests() };
is(scalar(@puts), 1, 'F7: CREATE ROLE sends one PUT (object-access hook cannot see the new role)');

$node->stop;
kill 'TERM', $mock_pid;
waitpid($mock_pid, 0);

done_testing();
