/* bubblewrap
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define HTTP_PROXY_PORT 8080
#define HTTP_PROXY_SANDBOX_PATH "/tmp/bwrap-http-proxy.sock"
#define HTTP_PROXY_HOST_MAX 254

typedef struct HttpAllowList HttpAllowList;

typedef enum {
  HTTP_PROXY_REQ_INVALID = 0,
  HTTP_PROXY_REQ_CONNECT,
  HTTP_PROXY_REQ_HTTP,
} HttpProxyReqKind;

HttpAllowList *http_allow_list_new (void);
void           http_allow_list_free (HttpAllowList *list);
int            http_allow_list_add (HttpAllowList *list,
                                    const char    *host);
bool           http_allow_list_empty (const HttpAllowList *list);
const char * const *http_allow_list_hosts (const HttpAllowList *list);
size_t         http_allow_list_len (const HttpAllowList *list);

int  http_proxy_normalize_host (const char *in,
                                char       *out,
                                size_t      out_size);
bool http_proxy_host_is_allowed (const char        *host,
                                 const char * const *allow,
                                 size_t             n);
bool http_proxy_sockaddr_blocked (const struct sockaddr *sa,
                                  socklen_t              len);
int  http_proxy_parse_request_line (const char      *line,
                                    HttpProxyReqKind *kind,
                                    char            *host,
                                    size_t           host_size,
                                    uint16_t        *port);

int  http_proxy_listen_unix (const char *path);
int  http_proxy_listen_loopback (uint16_t port);
void http_proxy_run_server (int                 listen_fd,
                            const char * const *allow,
                            size_t              n);
void http_proxy_run_tcp_shim (int         listen_fd,
                              const char *unix_path);
void http_proxy_inject_env (void);
