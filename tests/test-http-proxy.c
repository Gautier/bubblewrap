/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "http-proxy.h"
#include "utils.h"

static unsigned int test_number = 0;

__attribute__((format(printf, 1, 2)))
static void
ok (const char *format, ...)
{
  va_list ap;

  printf ("ok %u - ", ++test_number);
  va_start (ap, format);
  vprintf (format, ap);
  va_end (ap);
  printf ("\n");
}

#define not_ok(fmt, ...) die (fmt, ## __VA_ARGS__)

#define g_assert_cmpstr(left_expr, op, right_expr) \
  do { \
    const char *left = (left_expr); \
    const char *right = (right_expr); \
    if (strcmp (left, right) op 0) \
      ok ("%s (\"%s\") %s %s (\"%s\")", #left_expr, left, #op, #right_expr, right); \
    else \
      not_ok ("expected %s (\"%s\") %s %s (\"%s\")", \
              #left_expr, left, #op, #right_expr, right); \
  } while (0)
#define g_assert_cmpint(left_expr, op, right_expr) \
  do { \
    intmax_t left = (left_expr); \
    intmax_t right = (right_expr); \
    if (left op right) \
      ok ("%s (%ji) %s %s (%ji)", #left_expr, left, #op, #right_expr, right); \
    else \
      not_ok ("expected %s (%ji) %s %s (%ji)", \
              #left_expr, left, #op, #right_expr, right); \
  } while (0)
#define g_assert_true(expr) \
  do { \
    if ((expr)) \
      ok ("%s", #expr); \
    else \
      not_ok ("expected %s to be true", #expr); \
  } while (0)
#define g_assert_false(expr) \
  do { \
    if (!(expr)) \
      ok ("!(%s)", #expr); \
    else \
      not_ok ("expected %s to be false", #expr); \
  } while (0)

static int
normalize_ok (const char *in,
              char       *out)
{
  return http_proxy_normalize_host (in, out, HTTP_PROXY_HOST_MAX);
}

static void
test_normalize_host (void)
{
  char out[HTTP_PROXY_HOST_MAX];

  g_assert_cmpint (normalize_ok ("api.anthropic.com", out), ==, 0);
  g_assert_cmpstr (out, ==, "api.anthropic.com");

  g_assert_cmpint (normalize_ok ("API.Anthropic.COM", out), ==, 0);
  g_assert_cmpstr (out, ==, "api.anthropic.com");

  g_assert_cmpint (normalize_ok ("google.com.", out), ==, 0);
  g_assert_cmpstr (out, ==, "google.com");

  g_assert_cmpint (normalize_ok ("localhost", out), ==, 0);
  g_assert_cmpstr (out, ==, "localhost");

  g_assert_cmpint (normalize_ok ("google.com..", out), ==, 0);
  g_assert_cmpstr (out, ==, "google.com");
  g_assert_cmpint (normalize_ok ("google..com", out), ==, -1);
  g_assert_cmpint (normalize_ok ("-foo.com", out), ==, -1);
  g_assert_cmpint (normalize_ok ("foo-.com", out), ==, -1);
  g_assert_cmpint (normalize_ok ("*.google.com", out), ==, -1);
  g_assert_cmpint (normalize_ok ("google.com/path", out), ==, -1);
  g_assert_cmpint (normalize_ok ("127.0.0.1", out), ==, -1);
  g_assert_cmpint (normalize_ok ("8.8.8.8", out), ==, -1);
  g_assert_cmpint (normalize_ok ("::1", out), ==, -1);
  g_assert_cmpint (normalize_ok ("user@host.com", out), ==, -1);
  g_assert_cmpint (normalize_ok ("host:443", out), ==, -1);
}

static void
test_allow_list (void)
{
  HttpAllowList *list = http_allow_list_new ();
  const char *const *hosts;

  g_assert_true (http_allow_list_empty (NULL));
  g_assert_true (http_allow_list_empty (list));

  g_assert_cmpint (http_allow_list_add (list, "api.anthropic.com"), ==, 0);
  g_assert_cmpint (http_allow_list_add (list, "Google.COM"), ==, 0);
  g_assert_cmpint (http_allow_list_add (list, "google.com"), ==, 0);
  g_assert_cmpint (http_allow_list_add (list, "*.example.com"), ==, -1);
  g_assert_cmpint (http_allow_list_add (list, "1.2.3.4"), ==, -1);

  g_assert_false (http_allow_list_empty (list));
  g_assert_cmpint ((intmax_t) http_allow_list_len (list), ==, 2);

  hosts = http_allow_list_hosts (list);
  g_assert_true (http_proxy_host_is_allowed ("api.anthropic.com", hosts, http_allow_list_len (list)));
  g_assert_true (http_proxy_host_is_allowed ("GOOGLE.com", hosts, http_allow_list_len (list)));
  g_assert_false (http_proxy_host_is_allowed ("www.google.com", hosts, http_allow_list_len (list)));
  g_assert_false (http_proxy_host_is_allowed ("evil.api.anthropic.com", hosts, http_allow_list_len (list)));
  g_assert_false (http_proxy_host_is_allowed ("example.org", hosts, http_allow_list_len (list)));

  http_allow_list_free (list);
}

static void
test_parse_request_line (void)
{
  HttpProxyReqKind kind;
  char host[HTTP_PROXY_HOST_MAX];
  uint16_t port;

  g_assert_cmpint (http_proxy_parse_request_line ("CONNECT api.anthropic.com:443 HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, 0);
  g_assert_cmpint (kind, ==, HTTP_PROXY_REQ_CONNECT);
  g_assert_cmpstr (host, ==, "api.anthropic.com");
  g_assert_cmpint (port, ==, 443);

  g_assert_cmpint (http_proxy_parse_request_line ("CONNECT Google.COM:443 HTTP/1.0",
                                                  &kind, host, sizeof host, &port), ==, 0);
  g_assert_cmpstr (host, ==, "google.com");

  g_assert_cmpint (http_proxy_parse_request_line ("CONNECT example.com:80 HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, 0);
  g_assert_cmpint (port, ==, 80);

  g_assert_cmpint (http_proxy_parse_request_line ("CONNECT 127.0.0.1:443 HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, -1);
  g_assert_cmpint (http_proxy_parse_request_line ("CONNECT [ ::1 ]:443 HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, -1);
  g_assert_cmpint (http_proxy_parse_request_line ("CONNECT example.com HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, -1);

  g_assert_cmpint (http_proxy_parse_request_line ("GET http://google.com/foo HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, 0);
  g_assert_cmpint (kind, ==, HTTP_PROXY_REQ_HTTP);
  g_assert_cmpstr (host, ==, "google.com");
  g_assert_cmpint (port, ==, 80);

  g_assert_cmpint (http_proxy_parse_request_line ("GET http://google.com HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, 0);
  g_assert_cmpint (port, ==, 80);

  g_assert_cmpint (http_proxy_parse_request_line ("POST http://example.com:80/x HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, 0);
  g_assert_cmpint (port, ==, 80);

  g_assert_cmpint (http_proxy_parse_request_line ("GET http://example.com:8080/x HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, 0);
  g_assert_cmpint (port, ==, 8080);

  g_assert_cmpint (http_proxy_parse_request_line ("GET https://google.com/ HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, -1);
  g_assert_cmpint (http_proxy_parse_request_line ("GET /relative HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, -1);
  g_assert_cmpint (http_proxy_parse_request_line ("GET http://127.0.0.1/ HTTP/1.1",
                                                  &kind, host, sizeof host, &port), ==, -1);
}

static void
test_sockaddr_blocked (void)
{
  struct sockaddr_in in;
  struct sockaddr_in6 in6;

  memset (&in, 0, sizeof in);
  in.sin_family = AF_INET;

  in.sin_addr.s_addr = htonl (0x7f000001u);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, sizeof in));

  in.sin_addr.s_addr = htonl (0x0a000001u);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, sizeof in));

  in.sin_addr.s_addr = htonl (0xc0a80001u);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, sizeof in));

  in.sin_addr.s_addr = htonl (0xac100001u);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, sizeof in));

  in.sin_addr.s_addr = htonl (0xa9fe0001u);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, sizeof in));

  in.sin_addr.s_addr = htonl (0x64400001u);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, sizeof in));

  in.sin_addr.s_addr = htonl (0x08080808u);
  g_assert_false (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, sizeof in));

  in.sin_addr.s_addr = htonl (0x08080808u);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in, 1));

  memset (&in6, 0, sizeof in6);
  in6.sin6_family = AF_INET6;
  in6.sin6_addr = in6addr_loopback;
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in6, sizeof in6));

  /* 2001:4860:4860::8888 */
  inet_pton (AF_INET6, "2001:4860:4860::8888", &in6.sin6_addr);
  g_assert_false (http_proxy_sockaddr_blocked ((struct sockaddr *) &in6, sizeof in6));

  inet_pton (AF_INET6, "fc00::1", &in6.sin6_addr);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in6, sizeof in6));

  inet_pton (AF_INET6, "fe80::1", &in6.sin6_addr);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in6, sizeof in6));

  /* IPv4-mapped loopback */
  inet_pton (AF_INET6, "::ffff:127.0.0.1", &in6.sin6_addr);
  g_assert_true (http_proxy_sockaddr_blocked ((struct sockaddr *) &in6, sizeof in6));
}

int
main (int argc UNUSED,
      char **argv UNUSED)
{
  setvbuf (stdout, NULL, _IONBF, 0);
  test_normalize_host ();
  test_allow_list ();
  test_parse_request_line ();
  test_sockaddr_blocked ();
  printf ("1..%u\n", test_number);
  return 0;
}
