/* bubblewrap
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#include "config.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "http-proxy.h"
#include "utils.h"

#define HTTP_PROXY_HEADER_MAX 8192
#define HTTP_PROXY_TIMEOUT_MS 10000

struct HttpAllowList
{
  char  **hosts;
  size_t  n;
  size_t  alloc;
};

static bool
write_all (int         fd,
           const char *buf,
           size_t      len)
{
  while (len > 0)
    {
      ssize_t n;

      n = TEMP_FAILURE_RETRY (write (fd, buf, len));
      if (n <= 0)
        return false;
      buf += n;
      len -= (size_t) n;
    }

  return true;
}

static void
send_status (int         fd,
             const char *status)
{
  char buf[256];
  int n;

  n = snprintf (buf, sizeof buf,
                "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                status);
  if (n > 0 && (size_t) n < sizeof buf)
    write_all (fd, buf, (size_t) n);
}

static bool
ipv4_blocked (uint32_t addr)
{
  if ((addr & 0xff000000u) == 0x7f000000u) /* 127.0.0.0/8 */
    return true;
  if ((addr & 0xff000000u) == 0x0a000000u) /* 10.0.0.0/8 */
    return true;
  if ((addr & 0xfff00000u) == 0xac100000u) /* 172.16.0.0/12 */
    return true;
  if ((addr & 0xffff0000u) == 0xc0a80000u) /* 192.168.0.0/16 */
    return true;
  if ((addr & 0xffff0000u) == 0xa9fe0000u) /* 169.254.0.0/16 */
    return true;
  if ((addr & 0xffc00000u) == 0x64400000u) /* 100.64.0.0/10 */
    return true;
  if ((addr & 0xff000000u) == 0x00000000u) /* 0.0.0.0/8 */
    return true;
  if ((addr & 0xf0000000u) == 0xe0000000u) /* 224.0.0.0/4 */
    return true;
  if (addr == 0xffffffffu)
    return true;
  return false;
}

int
http_proxy_normalize_host (const char *in,
                           char       *out,
                           size_t      out_size)
{
  char tmp[HTTP_PROXY_HOST_MAX];
  struct in_addr addr;
  size_t i;
  size_t j;
  size_t label_len;

  if (in == NULL || in[0] == '\0' || out == NULL || out_size == 0)
    return -1;

  if (strchr (in, ':') != NULL ||
      strchr (in, '/') != NULL ||
      strchr (in, '\\') != NULL ||
      strchr (in, ' ') != NULL ||
      strchr (in, '*') != NULL ||
      strchr (in, '%') != NULL ||
      strchr (in, '@') != NULL ||
      strchr (in, '?') != NULL ||
      strchr (in, '#') != NULL)
    return -1;

  j = 0;
  for (i = 0; in[i] != '\0'; i++)
    {
      unsigned char c = (unsigned char) in[i];

      if (c >= 128)
        return -1;
      if (j + 1 >= sizeof tmp)
        return -1;
      if (c >= 'A' && c <= 'Z')
        c = (unsigned char) (c - 'A' + 'a');
      tmp[j++] = (char) c;
    }

  while (j > 0 && tmp[j - 1] == '.')
    j--;
  tmp[j] = '\0';
  if (j == 0)
    return -1;

  if (inet_pton (AF_INET, tmp, &addr) == 1)
    return -1;

  label_len = 0;
  for (i = 0; i <= j; i++)
    {
      char c = tmp[i];

      if (c == '.' || c == '\0')
        {
          if (label_len == 0)
            return -1;
          if (tmp[i - label_len] == '-' || tmp[i - 1] == '-')
            return -1;
          label_len = 0;
        }
      else
        {
          if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return -1;
          label_len++;
          if (label_len > 63)
            return -1;
        }
    }

  if (j + 1 > out_size)
    return -1;
  memcpy (out, tmp, j + 1);
  return 0;
}

bool
http_proxy_host_is_allowed (const char        *host,
                            const char * const *allow,
                            size_t             n)
{
  char normalized[HTTP_PROXY_HOST_MAX];
  size_t i;

  if (host == NULL || allow == NULL)
    return false;
  if (http_proxy_normalize_host (host, normalized, sizeof normalized) != 0)
    return false;

  for (i = 0; i < n; i++)
    {
      if (allow[i] != NULL && strcmp (allow[i], normalized) == 0)
        return true;
    }

  return false;
}

bool
http_proxy_sockaddr_blocked (const struct sockaddr *sa,
                             socklen_t              len)
{
  if (sa == NULL)
    return true;

  if (sa->sa_family == AF_INET)
    {
      const struct sockaddr_in *in = (const struct sockaddr_in *) sa;

      if (len < (socklen_t) sizeof (*in))
        return true;
      return ipv4_blocked (ntohl (in->sin_addr.s_addr));
    }

  if (sa->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) sa;
      struct in6_addr a;

      if (len < (socklen_t) sizeof (*in6))
        return true;
      a = in6->sin6_addr;

      if (IN6_IS_ADDR_V4MAPPED (&a))
        {
          uint32_t v4;

          memcpy (&v4, &a.s6_addr[12], 4);
          return ipv4_blocked (ntohl (v4));
        }

      if (IN6_IS_ADDR_LOOPBACK (&a) ||
          IN6_IS_ADDR_LINKLOCAL (&a) ||
          IN6_IS_ADDR_SITELOCAL (&a) ||
          IN6_IS_ADDR_MULTICAST (&a) ||
          IN6_IS_ADDR_UNSPECIFIED (&a))
        return true;

      /* Unique local fc00::/7 */
      if ((a.s6_addr[0] & 0xfe) == 0xfc)
        return true;

      return false;
    }

  return true;
}

int
http_proxy_parse_request_line (const char       *line,
                               HttpProxyReqKind *kind,
                               char             *host,
                               size_t            host_size,
                               uint16_t         *port)
{
  const char *p;
  char method[16];
  size_t mlen = 0;

  if (kind != NULL)
    *kind = HTTP_PROXY_REQ_INVALID;
  if (port != NULL)
    *port = 0;
  if (host != NULL && host_size > 0)
    host[0] = '\0';

  if (line == NULL || kind == NULL || host == NULL || port == NULL || host_size == 0)
    return -1;

  p = line;
  while (*p == ' ')
    p++;

  while (*p != '\0' && *p != ' ')
    {
      if (mlen + 1 >= sizeof method)
        return -1;
      method[mlen++] = *p++;
    }
  method[mlen] = '\0';
  if (*p != ' ')
    return -1;
  while (*p == ' ')
    p++;

  if (strcmp (method, "CONNECT") == 0)
    {
      const char *end;
      const char *colon;
      char hostbuf[HTTP_PROXY_HOST_MAX];
      unsigned long prt;
      char *endptr;

      end = p;
      while (*end != '\0' && *end != ' ')
        end++;
      if (end == p || *p == '[')
        return -1;

      colon = memchr (p, ':', (size_t) (end - p));
      if (colon == NULL || colon == p)
        return -1;
      if ((size_t) (colon - p) >= sizeof hostbuf)
        return -1;
      memcpy (hostbuf, p, (size_t) (colon - p));
      hostbuf[colon - p] = '\0';

      errno = 0;
      prt = strtoul (colon + 1, &endptr, 10);
      if (errno != 0 || endptr != end || prt == 0 || prt > 65535)
        return -1;
      if (http_proxy_normalize_host (hostbuf, host, host_size) != 0)
        return -1;
      *port = (uint16_t) prt;
      *kind = HTTP_PROXY_REQ_CONNECT;
      return 0;
    }

  if (!has_prefix (p, "http://"))
    return -1;
  p += strlen ("http://");
  {
    const char *host_end = p;
    char hostbuf[HTTP_PROXY_HOST_MAX];
    unsigned long prt = 80;

    if (*p == '[')
      return -1;

    while (*host_end != '\0' &&
           *host_end != '/' &&
           *host_end != ' ' &&
           *host_end != '?' &&
           *host_end != '#' &&
           *host_end != ':')
      host_end++;

    if (host_end == p)
      return -1;
    if ((size_t) (host_end - p) >= sizeof hostbuf)
      return -1;
    memcpy (hostbuf, p, (size_t) (host_end - p));
    hostbuf[host_end - p] = '\0';

    if (*host_end == ':')
      {
        char *endptr;

        errno = 0;
        prt = strtoul (host_end + 1, &endptr, 10);
        if (errno != 0 || endptr == host_end + 1 || prt == 0 || prt > 65535)
          return -1;
        if (*endptr != '/' && *endptr != ' ' && *endptr != '?' &&
            *endptr != '#' && *endptr != '\0')
          return -1;
      }

    if (http_proxy_normalize_host (hostbuf, host, host_size) != 0)
      return -1;
    *port = (uint16_t) prt;
    *kind = HTTP_PROXY_REQ_HTTP;
    return 0;
  }
}

HttpAllowList *
http_allow_list_new (void)
{
  return xcalloc (1, sizeof (HttpAllowList));
}

void
http_allow_list_free (HttpAllowList *list)
{
  if (list == NULL)
    return;
  strfreev (list->hosts);
  free (list);
}

int
http_allow_list_add (HttpAllowList *list,
                     const char    *host)
{
  char normalized[HTTP_PROXY_HOST_MAX];
  size_t i;

  if (list == NULL)
    return -1;
  if (http_proxy_normalize_host (host, normalized, sizeof normalized) != 0)
    return -1;

  for (i = 0; i < list->n; i++)
    {
      if (strcmp (list->hosts[i], normalized) == 0)
        return 0;
    }

  if (list->n + 2 > list->alloc)
    {
      size_t na = list->alloc ? list->alloc * 2 : 8;

      list->hosts = xrealloc (list->hosts, na * sizeof (char *));
      list->alloc = na;
    }

  list->hosts[list->n] = xstrdup (normalized);
  list->n++;
  list->hosts[list->n] = NULL;
  return 0;
}

bool
http_allow_list_empty (const HttpAllowList *list)
{
  return list == NULL || list->n == 0;
}

const char * const *
http_allow_list_hosts (const HttpAllowList *list)
{
  if (list == NULL)
    return NULL;
  return (const char * const *) list->hosts;
}

size_t
http_allow_list_len (const HttpAllowList *list)
{
  if (list == NULL)
    return 0;
  return list->n;
}

static int
connect_timeout (int                    fd,
                 const struct sockaddr *sa,
                 socklen_t              len,
                 int                    timeout_ms)
{
  int flags;
  int err = 0;
  socklen_t errlen = sizeof err;
  struct pollfd pfd;

  flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;

  if (connect (fd, sa, len) < 0 && errno != EINPROGRESS)
    {
      fcntl (fd, F_SETFL, flags);
      return -1;
    }

  pfd.fd = fd;
  pfd.events = POLLOUT;
  pfd.revents = 0;
  if (poll (&pfd, 1, timeout_ms) <= 0)
    {
      fcntl (fd, F_SETFL, flags);
      errno = ETIMEDOUT;
      return -1;
    }

  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0)
    {
      fcntl (fd, F_SETFL, flags);
      errno = err != 0 ? err : ECONNREFUSED;
      return -1;
    }

  fcntl (fd, F_SETFL, flags);
  return 0;
}

static int
connect_allowed_host (const char        *host,
                      uint16_t           port,
                      const char * const *allow,
                      size_t             n_allow)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *ai;
  char portstr[8];
  int fd = -1;

  if (!http_proxy_host_is_allowed (host, allow, n_allow))
    {
      errno = EACCES;
      return -1;
    }

  memset (&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
  snprintf (portstr, sizeof portstr, "%u", port);

  if (getaddrinfo (host, portstr, &hints, &res) != 0)
    return -1;

  {
    int pass;

    for (pass = 0; pass < 2 && fd < 0; pass++)
      {
        int family = (pass == 0) ? AF_INET : AF_INET6;

        for (ai = res; ai != NULL; ai = ai->ai_next)
          {
            if (ai->ai_family != family)
              continue;
            if (http_proxy_sockaddr_blocked (ai->ai_addr, ai->ai_addrlen))
              continue;

            fd = socket (ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
            if (fd < 0)
              continue;
            if (connect_timeout (fd, ai->ai_addr, ai->ai_addrlen, 3000) == 0)
              break;
            close (fd);
            fd = -1;
          }
      }
  }

  freeaddrinfo (res);
  if (fd < 0)
    errno = EACCES;
  return fd;
}

static void
copy_bidirectional (int a,
                    int b)
{
  char abuf[16384];
  char bbuf[16384];
  size_t alen = 0;
  size_t blen = 0;
  bool a_read = true;
  bool b_read = true;
  bool a_write = true;
  bool b_write = true;
  int flags;

  flags = fcntl (a, F_GETFL, 0);
  if (flags >= 0)
    fcntl (a, F_SETFL, flags | O_NONBLOCK);
  flags = fcntl (b, F_GETFL, 0);
  if (flags >= 0)
    fcntl (b, F_SETFL, flags | O_NONBLOCK);

  while (a_read || b_read || alen > 0 || blen > 0)
    {
      struct pollfd fds[2];
      ssize_t n;

      fds[0].fd = a;
      fds[1].fd = b;
      fds[0].events = 0;
      fds[1].events = 0;
      fds[0].revents = 0;
      fds[1].revents = 0;

      if (a_read && alen < sizeof abuf)
        fds[0].events |= POLLIN;
      if (a_write && blen > 0)
        fds[0].events |= POLLOUT;
      if (b_read && blen < sizeof bbuf)
        fds[1].events |= POLLIN;
      if (b_write && alen > 0)
        fds[1].events |= POLLOUT;

      if (fds[0].events == 0 && fds[1].events == 0)
        break;

      if (poll (fds, 2, -1) < 0)
        {
          if (errno == EINTR)
            continue;
          return;
        }

      if (a_read && (fds[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
        {
          n = TEMP_FAILURE_RETRY (read (a, abuf + alen, sizeof abuf - alen));
          if (n > 0)
            {
              alen += (size_t) n;
            }
          else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
            {
              a_read = false;
              if (alen == 0 && b_write)
                {
                  shutdown (b, SHUT_WR);
                  b_write = false;
                }
            }
        }

      if (b_write && alen > 0 && (fds[1].revents & (POLLOUT | POLLERR | POLLNVAL)))
        {
          n = TEMP_FAILURE_RETRY (write (b, abuf, alen));
          if (n > 0)
            {
              alen -= (size_t) n;
              if (alen > 0)
                memmove (abuf, abuf + n, alen);
              if (!a_read && alen == 0 && b_write)
                {
                  shutdown (b, SHUT_WR);
                  b_write = false;
                }
            }
          else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
              return;
            }
        }

      if (b_read && (fds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
        {
          n = TEMP_FAILURE_RETRY (read (b, bbuf + blen, sizeof bbuf - blen));
          if (n > 0)
            {
              blen += (size_t) n;
            }
          else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
            {
              b_read = false;
              if (blen == 0 && a_write)
                {
                  shutdown (a, SHUT_WR);
                  a_write = false;
                }
            }
        }

      if (a_write && blen > 0 && (fds[0].revents & (POLLOUT | POLLERR | POLLNVAL)))
        {
          n = TEMP_FAILURE_RETRY (write (a, bbuf, blen));
          if (n > 0)
            {
              blen -= (size_t) n;
              if (blen > 0)
                memmove (bbuf, bbuf + n, blen);
              if (!b_read && blen == 0 && a_write)
                {
                  shutdown (a, SHUT_WR);
                  a_write = false;
                }
            }
          else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
              return;
            }
        }
    }
}

static const char *
find_headers_end (const char *buf,
                  size_t     *eol_len)
{
  const char *p;

  p = strstr (buf, "\r\n\r\n");
  if (p != NULL)
    {
      *eol_len = 4;
      return p;
    }
  p = strstr (buf, "\n\n");
  if (p != NULL)
    {
      *eol_len = 2;
      return p;
    }
  return NULL;
}

static int
read_headers (int     fd,
              char   *buf,
              size_t  cap,
              size_t *out_len)
{
  size_t n = 0;

  while (n + 1 < cap)
    {
      struct pollfd pfd;
      ssize_t k;
      size_t dummy;

      pfd.fd = fd;
      pfd.events = POLLIN;
      pfd.revents = 0;
      if (poll (&pfd, 1, HTTP_PROXY_TIMEOUT_MS) <= 0)
        return -1;

      k = TEMP_FAILURE_RETRY (read (fd, buf + n, cap - 1 - n));
      if (k <= 0)
        return -1;
      n += (size_t) k;
      buf[n] = '\0';
      if (find_headers_end (buf, &dummy) != NULL)
        {
          *out_len = n;
          return 0;
        }
    }

  return -1;
}

static bool
header_is_hop_by_hop (const char *line)
{
  static const char *const skip[] = {
    "proxy-connection:",
    "proxy-authorization:",
    "proxy-authenticate:",
  };
  size_t i;

  for (i = 0; i < N_ELEMENTS (skip); i++)
    {
      size_t len = strlen (skip[i]);
      if (strncasecmp (line, skip[i], len) == 0)
        return true;
    }
  return false;
}

static bool
build_origin_request (const char *buf,
                      size_t      len,
                      char       *out,
                      size_t      out_size,
                      size_t     *out_len)
{
  const char *line_end;
  const char *sp;
  const char *uri;
  const char *path;
  const char *version;
  const char *rest;
  size_t method_len;
  size_t n = 0;
  int crlf = 2;

  line_end = strstr (buf, "\r\n");
  if (line_end == NULL)
    {
      line_end = strchr (buf, '\n');
      crlf = 1;
    }
  if (line_end == NULL)
    return false;

  sp = memchr (buf, ' ', (size_t) (line_end - buf));
  if (sp == NULL)
    return false;
  method_len = (size_t) (sp - buf);
  uri = sp + 1;
  while (uri < line_end && *uri == ' ')
    uri++;
  if (!has_prefix (uri, "http://"))
    return false;

  path = uri + strlen ("http://");
  while (path < line_end &&
         *path != '/' && *path != '?' && *path != '#' && *path != ' ')
    path++;

  version = line_end;
  while (version > uri && version[-1] != ' ')
    version--;
  if (version == uri)
    return false;

  if (n + method_len + 1 >= out_size)
    return false;
  memcpy (out + n, buf, method_len);
  n += method_len;
  out[n++] = ' ';

  if (path < line_end && (*path == '/' || *path == '?' || *path == '#'))
    {
      size_t path_len = (size_t) (version - path);

      while (path_len > 0 && path[path_len - 1] == ' ')
        path_len--;
      if (n + path_len >= out_size)
        return false;
      memcpy (out + n, path, path_len);
      n += path_len;
    }
  else
    {
      if (n + 1 >= out_size)
        return false;
      out[n++] = '/';
    }

  out[n++] = ' ';
  {
    size_t vlen = (size_t) (line_end - version);

    if (n + vlen + (size_t) crlf >= out_size)
      return false;
    memcpy (out + n, version, vlen);
    n += vlen;
  }
  if (crlf == 2)
    {
      out[n++] = '\r';
      out[n++] = '\n';
    }
  else
    {
      out[n++] = '\n';
    }

  rest = line_end + crlf;
  while (rest < buf + len)
    {
      const char *next = strstr (rest, "\r\n");
      size_t line_len;
      int leol = 2;

      if (next == NULL)
        {
          next = strchr (rest, '\n');
          leol = 1;
        }
      if (next == NULL)
        {
          line_len = (size_t) (buf + len - rest);
          if (n + line_len >= out_size)
            return false;
          memcpy (out + n, rest, line_len);
          n += line_len;
          break;
        }

      line_len = (size_t) (next - rest);
      if (line_len == 0)
        {
          /* end of headers */
          if (n + (size_t) leol + (size_t) (buf + len - (next + leol)) >= out_size)
            return false;
          memcpy (out + n, rest, (size_t) (buf + len - rest));
          n += (size_t) (buf + len - rest);
          break;
        }

      if (!header_is_hop_by_hop (rest))
        {
          if (n + line_len + (size_t) leol >= out_size)
            return false;
          memcpy (out + n, rest, line_len + (size_t) leol);
          n += line_len + (size_t) leol;
        }
      rest = next + leol;
    }

  *out_len = n;
  return true;
}

static void
handle_client (int                 client_fd,
               const char * const *allow,
               size_t              n_allow)
{
  char buf[HTTP_PROXY_HEADER_MAX];
  char line[1024];
  char host[HTTP_PROXY_HOST_MAX];
  char origin_req[HTTP_PROXY_HEADER_MAX + 16];
  size_t n = 0;
  size_t line_len;
  size_t origin_len = 0;
  const char *eol;
  HttpProxyReqKind kind;
  uint16_t port;
  int origin_fd;

  if (read_headers (client_fd, buf, sizeof buf, &n) != 0)
    return;

  eol = strstr (buf, "\r\n");
  if (eol == NULL)
    eol = strchr (buf, '\n');
  if (eol == NULL)
    return;
  line_len = (size_t) (eol - buf);
  if (line_len >= sizeof line)
    {
      send_status (client_fd, "400 Bad Request");
      return;
    }
  memcpy (line, buf, line_len);
  line[line_len] = '\0';

  if (http_proxy_parse_request_line (line, &kind, host, sizeof host, &port) != 0)
    {
      send_status (client_fd, "400 Bad Request");
      return;
    }

  if (kind == HTTP_PROXY_REQ_CONNECT)
    {
      if (port != 443)
        {
          send_status (client_fd, "403 Forbidden");
          return;
        }
    }
  else if (kind == HTTP_PROXY_REQ_HTTP)
    {
      if (port != 80)
        {
          send_status (client_fd, "403 Forbidden");
          return;
        }
    }
  else
    {
      send_status (client_fd, "400 Bad Request");
      return;
    }

  if (!http_proxy_host_is_allowed (host, allow, n_allow))
    {
      send_status (client_fd, "403 Forbidden");
      return;
    }

  origin_fd = connect_allowed_host (host, port, allow, n_allow);
  if (origin_fd < 0)
    {
      send_status (client_fd, errno == EACCES ? "403 Forbidden" : "502 Bad Gateway");
      return;
    }

  if (kind == HTTP_PROXY_REQ_CONNECT)
    {
      size_t dummy;
      const char *hend;

      if (!write_all (client_fd, "HTTP/1.1 200 Connection Established\r\n\r\n",
                      strlen ("HTTP/1.1 200 Connection Established\r\n\r\n")))
        {
          close (origin_fd);
          return;
        }

      hend = find_headers_end (buf, &dummy);
      if (hend != NULL)
        {
          const char *extra = hend + dummy;

          if (extra < buf + n)
            {
              if (!write_all (origin_fd, extra, (size_t) (buf + n - extra)))
                {
                  close (origin_fd);
                  return;
                }
            }
        }

      copy_bidirectional (client_fd, origin_fd);
    }
  else
    {
      if (!build_origin_request (buf, n, origin_req, sizeof origin_req, &origin_len) ||
          !write_all (origin_fd, origin_req, origin_len))
        {
          close (origin_fd);
          send_status (client_fd, "400 Bad Request");
          return;
        }
      copy_bidirectional (client_fd, origin_fd);
    }

  close (origin_fd);
}

int
http_proxy_listen_unix (const char *path)
{
  struct sockaddr_un addr;
  int fd;
  int one = 1;

  if (path == NULL || path[0] == '\0')
    {
      errno = EINVAL;
      return -1;
    }
  if (strlen (path) >= sizeof addr.sun_path)
    {
      errno = ENAMETOOLONG;
      return -1;
    }

  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;

  memset (&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  memcpy (addr.sun_path, path, strlen (path) + 1);
  unlink (path);

  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0)
    {
      /* ignore */
    }

  if (bind (fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    {
      close (fd);
      return -1;
    }

  if (chmod (path, 0666) < 0)
    {
      close (fd);
      unlink (path);
      return -1;
    }

  if (listen (fd, 128) < 0)
    {
      close (fd);
      unlink (path);
      return -1;
    }

  return fd;
}

int
http_proxy_listen_loopback (uint16_t port)
{
  int fd;
  int one = 1;
  struct sockaddr_in addr;

  fd = socket (AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;

  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0)
    {
      close (fd);
      return -1;
    }

  memset (&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  if (bind (fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    {
      close (fd);
      return -1;
    }
  if (listen (fd, 128) < 0)
    {
      close (fd);
      return -1;
    }

  return fd;
}

void
http_proxy_run_server (int                 listen_fd,
                       const char * const *allow,
                       size_t              n)
{
  signal (SIGPIPE, SIG_IGN);
  signal (SIGCHLD, SIG_IGN);

  for (;;)
    {
      int cfd;
      pid_t pid;

      cfd = TEMP_FAILURE_RETRY (accept (listen_fd, NULL, NULL));
      if (cfd < 0)
        continue;

      pid = fork ();
      if (pid == -1)
        {
          close (cfd);
          continue;
        }
      if (pid != 0)
        {
          close (cfd);
          continue;
        }

      if (prctl (PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
        _exit (1);
      close (listen_fd);
      handle_client (cfd, allow, n);
      close (cfd);
      _exit (0);
    }
}

void
http_proxy_run_tcp_shim (int         listen_fd,
                         const char *unix_path)
{
  signal (SIGPIPE, SIG_IGN);
  signal (SIGCHLD, SIG_IGN);

  for (;;)
    {
      int cfd;
      int ufd;
      pid_t pid;
      struct sockaddr_un un;

      cfd = TEMP_FAILURE_RETRY (accept (listen_fd, NULL, NULL));
      if (cfd < 0)
        continue;

      pid = fork ();
      if (pid == -1)
        {
          close (cfd);
          continue;
        }
      if (pid != 0)
        {
          close (cfd);
          continue;
        }

      if (prctl (PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
        _exit (1);
      close (listen_fd);

      ufd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (ufd < 0)
        _exit (1);

      memset (&un, 0, sizeof un);
      un.sun_family = AF_UNIX;
      if (strlen (unix_path) >= sizeof un.sun_path)
        _exit (1);
      memcpy (un.sun_path, unix_path, strlen (unix_path) + 1);
      if (connect (ufd, (struct sockaddr *) &un, sizeof un) < 0)
        _exit (1);

      copy_bidirectional (cfd, ufd);
      close (cfd);
      close (ufd);
      _exit (0);
    }
}

void
http_proxy_inject_env (void)
{
  const char *url = "http://127.0.0.1:8080";

  xsetenv ("http_proxy", url, 1);
  xsetenv ("https_proxy", url, 1);
  xsetenv ("HTTP_PROXY", url, 1);
  xsetenv ("HTTPS_PROXY", url, 1);
  xsetenv ("ALL_PROXY", url, 1);
  xunsetenv ("NO_PROXY");
  xunsetenv ("no_proxy");
}
