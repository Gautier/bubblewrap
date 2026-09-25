#!/usr/bin/env bash

set -euo pipefail

srcd=$(cd "$(dirname "$0")" && pwd)

. "${srcd}/libtest.sh"

test_count=0
ok () {
    test_count=$((test_count + 1))
    echo "ok $test_count - $*"
}
ok_skip () {
    ok "# SKIP $*"
}
done_testing () {
    echo "1..$test_count"
}

${BWRAP} --help > help.txt
assert_file_has_content help.txt --http-allow
ok "help mentions --http-allow"

if $RUN --http-allow '' true 2>err.txt; then
    assert_not_reached "empty --http-allow accepted"
fi
assert_file_has_content err.txt "invalid host name"
ok "empty host rejected"

if $RUN --http-allow '*.google.com' true 2>err.txt; then
    assert_not_reached "wildcard --http-allow accepted"
fi
assert_file_has_content err.txt "invalid host name"
ok "wildcard host rejected"

if $RUN --http-allow 1.2.3.4 true 2>err.txt; then
    assert_not_reached "IP --http-allow accepted"
fi
assert_file_has_content err.txt "invalid host name"
ok "IP host rejected"

if $RUN --share-net --http-allow example.com true 2>err.txt; then
    assert_not_reached "--share-net with --http-allow accepted"
fi
assert_file_has_content err.txt "cannot be combined with --share-net"
ok "--share-net then --http-allow rejected"

if $RUN --http-allow example.com --share-net true 2>err.txt; then
    assert_not_reached "--http-allow with --share-net accepted"
fi
assert_file_has_content err.txt "cannot be combined with --share-net"
ok "--http-allow then --share-net rejected"

$RUN --http-allow example.com printenv https_proxy > stdout
assert_file_has_content stdout '^http://127.0.0.1:8080$'
ok "sets https_proxy"

$RUN --http-allow example.com printenv HTTP_PROXY > stdout
assert_file_has_content stdout '^http://127.0.0.1:8080$'
ok "sets HTTP_PROXY"

if $RUN --http-allow example.com printenv NO_PROXY > stdout 2>/dev/null; then
    if test -s stdout; then
        assert_not_reached "NO_PROXY should be unset"
    fi
fi
ok "clears NO_PROXY"

if ! command -v curl >/dev/null; then
    ok_skip "curl not installed"
    done_testing
    exit 0
fi

if $RUN --http-allow example.com curl -sS -o /dev/null --max-time 5 http://127.0.0.1/; then
    assert_not_reached "loopback HTTP via proxy should be denied"
fi
ok "proxy denies loopback origin"

if $RUN --http-allow example.com curl -sS -o /dev/null --max-time 5 https://example.org; then
    assert_not_reached "disallowed host succeeded"
fi
ok "disallowed host is blocked"

if curl -sS -o /dev/null --max-time 5 https://example.com; then
    if ! $RUN --http-allow example.com curl -sS --max-time 15 -o /tmp/http-allow-out https://example.com; then
        assert_not_reached "allowed host failed"
    fi
    ok "allowed host works"
else
    ok_skip "no network to example.com"
fi

done_testing
