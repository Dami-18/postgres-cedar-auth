
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use IO::Socket::INET;

# Find a free port for the mock service
my $sock = IO::Socket::INET->new(
	Listen    => 5,
	LocalAddr => '127.0.0.1',
	Proto     => 'tcp'
);
die "Cannot find free port: $!" unless $sock;
my $port = $sock->sockport;
$sock->close;

# Start mock Cedar service
my $mock_pid = fork();
if ($mock_pid == 0) {
    # Child process
    # Use -u for unbuffered output so we can see logs if needed
    exec("python3", "-u", "t/mock_cedar.py", "--port", $port);
    exit 1;
}

# Wait for mock service to start
my $retries = 20;
my $started = 0;
while ($retries-- > 0) {
    if (system("curl -s http://localhost:$port/health > /dev/null") == 0) {
        $started = 1;
        last;
    }
    sleep 1;
}
die "Mock service failed to start on port $port" unless $started;

# Initialize and start a node
my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_authorization'");
$node->start;

# Setup extension and configuration
$node->safe_psql('postgres', 'CREATE EXTENSION pg_authorization');
$node->safe_psql('postgres', "ALTER SYSTEM SET pg_authorization.cedar_agent_url = 'http://localhost:$port'");
$node->safe_psql('postgres', "SELECT pg_reload_conf()");

# Helper to get entities from mock service
sub get_entities {
    my $json = qx(curl -s http://localhost:$port/test/entities);
    return $json;
}

# --- Test 1: Entity Sync (Users) ---
$node->safe_psql('postgres', "CREATE ROLE alice LOGIN");
my $entities = get_entities();
ok($entities =~ /"alice"/, "Role 'alice' was synced to Cedar");

# --- Test 2: Entity Sync (Tables) ---
$node->safe_psql('postgres', "CREATE TABLE public.test_sync (id int)");
$node->safe_psql('postgres', "REVOKE ALL ON TABLE public.test_sync FROM PUBLIC");
$node->safe_psql('postgres', "REVOKE ALL ON SCHEMA public FROM PUBLIC");
$entities = get_entities();
ok($entities =~ /"public.test_sync"/, "Table 'public.test_sync' was synced to Cedar");

# --- Test 2b: Entity Sync (Schemas) ---
$node->safe_psql('postgres', "CREATE SCHEMA test_schema");
$entities = get_entities();
ok($entities =~ /"test_schema"/, "Schema 'test_schema' was synced to Cedar");

# --- Test 3: Authorization (Grant) ---
# alice is allowed Select in mock.
my ($ret, $stdout, $stderr) = $node->psql('postgres', "SELECT * FROM public.test_sync", extra_params => ['-U', 'alice']);
is($ret, 0, "Alice authorized to SELECT by Cedar");

# --- Test 4: Authorization (Deny) ---
$node->safe_psql('postgres', "CREATE ROLE bob LOGIN");
($ret, $stdout, $stderr) = $node->psql('postgres', "SELECT * FROM public.test_sync", extra_params => ['-U', 'bob']);
isnt($ret, 0, "Bob denied SELECT by Cedar");
like($stderr, qr/permission denied/, "Error message indicates permission denied");

# --- Test 5: Entity Sync (Delete) ---
$node->safe_psql('postgres', "DROP TABLE public.test_sync");
$entities = get_entities();
ok($entities !~ /"public.test_sync"/, "Table 'public.test_sync' was deleted from Cedar");

# --- Test 6: Column-level Authorization ---
$node->safe_psql('postgres', "CREATE TABLE public.test_col (a int, b int)");
$node->safe_psql('postgres', "REVOKE ALL ON TABLE public.test_col FROM PUBLIC");
# Alice should be allowed by mock.
($ret, $stdout, $stderr) = $node->psql('postgres', "SELECT a FROM public.test_col", extra_params => ['-U', 'alice']);
is($ret, 0, "Alice authorized to SELECT column 'a' by Cedar");

# --- Test 7: Type-level Authorization ---
$node->safe_psql('postgres', "CREATE TYPE test_type AS (f1 int, f2 text)");
$node->safe_psql('postgres', "REVOKE ALL ON TYPE test_type FROM PUBLIC");
# Alice should be allowed by mock.
($ret, $stdout, $stderr) = $node->psql('postgres', "SELECT NULL::test_type", extra_params => ['-U', 'alice']);
is($ret, 0, "Alice authorized to use type 'test_type' by Cedar");

# Cleanup
$node->stop;
kill 'TERM', $mock_pid;
waitpid($mock_pid, 0);

done_testing();
