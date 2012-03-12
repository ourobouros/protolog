/* Apache module to emit log data in binary protocol buffer messages.
 *
 * Copyright (c) 2012, Rachel Kroll
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name of Rachel Kroll nor the names of contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"                        /* for ap_get_remote_logname */
#include "http_log.h"
#include "http_protocol.h"
#include "util_time.h"

#include "apachelog.pb-c.h"

typedef struct {
  apr_array_header_t* proto_logs;
  apr_array_header_t* server_proto_logs;
} protolog_state;

typedef struct {
  const char* filename;
  apr_file_t* log_handle;
} protolog_file;

static int kLogFlags = APR_WRITE | APR_APPEND | APR_CREATE | APR_LARGEFILE;
static apr_fileperms_t kLogPerms = APR_OS_DEFAULT;

static const char* kCookieHeader = "Cookie";
static const char* kReferrerHeader = "Referrer";
static const char* kRefererHeader = "Referer";     /* sigh. */
static const char* kUserAgentHeader = "User-Agent";

module AP_MODULE_DECLARE_DATA protolog_module;

/* --- Config directive handling --- */

static const char* add_log_file(cmd_parms* cmd, void* unused,
                                const char* log_filename) {
  protolog_state* pls = ap_get_module_config(cmd->server->module_config,
                                             &protolog_module);

  protolog_file* plf = (protolog_file*) apr_array_push(pls->proto_logs);
  plf->filename = log_filename;

  return NULL;
}

static const command_rec protolog_cmds[] = {
  AP_INIT_TAKE1("ProtoLog", add_log_file, NULL, RSRC_CONF,
                "the filename of the binary protobuf log."),
  { NULL }
};

static void* create_config(apr_pool_t* p, server_rec* s) {
  protolog_state* pls;

  pls = (protolog_state*) apr_pcalloc(p, sizeof(protolog_state));
  pls->proto_logs = apr_array_make(p, 0, sizeof(protolog_file));
  pls->server_proto_logs = NULL;

  return (void*) pls;
}

/* Point vhosts at the base list in case they don't have any local logs. */
static void* merge_config(apr_pool_t* p, void* basev, void* restv) {
  protolog_state* base = (protolog_state*) basev;
  protolog_state* rest = (protolog_state*) restv;

  rest->server_proto_logs = base->proto_logs;
  return rest;
}

/* --- Log file initialization --- */

static int open_log_array(apr_pool_t* p, server_rec* s,
                          apr_array_header_t* logs) {
  int i;

  protolog_file* log_array = (protolog_file*) logs->elts;

  for (i = 0; i < logs->nelts; ++i) {
    protolog_file* plf = &log_array[i];

    apr_file_t* fd;
    apr_status_t rv;

    rv = apr_file_open(&fd, plf->filename, kLogFlags, kLogPerms, p);

    if (rv != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                   "could not open protocol binary log file %s",
                   plf->filename);
      return DONE;
    }

    plf->log_handle = fd;
  }

  return OK;
}

/* Open all logs which might apply to this server. */
static int open_server_logs(apr_pool_t* p, server_rec* s) {
  protolog_state* pls = ap_get_module_config(s->module_config,
                                             &protolog_module);
  /* If this server has its own logs, open them. */
  if (pls->proto_logs->nelts) {
    return open_log_array(p, s, pls->proto_logs);
  }

  /* Otherwise, open the global (inherited) logs. */
  if (pls->server_proto_logs) {
    return open_log_array(p, s, pls->server_proto_logs);
  }

  return OK;
}

/* This is only called once, even if we have vhosts active! */
static int open_all_logs(apr_pool_t* pc, apr_pool_t* p, apr_pool_t* pt,
                         server_rec* s) {
  int res = OK;

  /* First, whatever is defined for the top-level server. */
  res = open_server_logs(p, s);

  /* Now handle any virtual servers. */
  for (s = s->next; (res == OK) && s; s = s->next) {
    res = open_server_logs(p, s);
  }

  return res;
}

/* --- Transaction formatting and logging to an actual file --- */

static int write_to_log_array(request_rec* r, apr_array_header_t* logs,
                              const char* buf, size_t buflen) {
  int i;
  protolog_file* log_array = (protolog_file*) logs->elts;

  for (i = 0; i < logs->nelts; ++i) {
    protolog_file* log = &log_array[i];

    apr_file_write(log->log_handle, buf, &buflen);
  }

  return OK;
}

static int build_netstring(const char* protomsg, unsigned long protomsg_len,
                           char** netstring, size_t* netstring_len) {
  char preamble[16];
  size_t preamble_len;

  char* temp_netstring;
  size_t temp_netstring_len;

  snprintf(preamble, sizeof(preamble), "%lu:", protomsg_len);
  preamble_len = strlen(preamble);

  temp_netstring_len = preamble_len + protomsg_len + 1;

  temp_netstring = malloc(temp_netstring_len);
  if (temp_netstring == NULL) {
    return DECLINED;
  }

  memcpy(&temp_netstring[0], preamble, preamble_len);
  memcpy(&temp_netstring[preamble_len], protomsg, protomsg_len);
  temp_netstring[preamble_len + protomsg_len] = ',';

  *netstring = temp_netstring;
  *netstring_len = temp_netstring_len;

  return OK;
}

/* Wrap our serialized protobuf in a netstring, then write to all logs. */
static int write_serialized_msg(request_rec* r, const char* msg,
                                size_t msg_len) {
  protolog_state* pls;
  char* netstring;
  size_t ns_len;

  if (build_netstring(msg, msg_len, &netstring, &ns_len) != OK) {
    return DECLINED;
  }

  pls = ap_get_module_config(r->server->module_config, &protolog_module);

  if (pls->proto_logs->nelts) {
    int ret = write_to_log_array(r, pls->proto_logs, netstring, ns_len);

    free(netstring);
    return ret;
  }

  if (pls->server_proto_logs) {
    int ret;
    ret = write_to_log_array(r, pls->server_proto_logs, netstring, ns_len);

    free(netstring);
    return ret;
  }

  free(netstring);
  return OK;
}

static void SET_BYTES(ProtobufCBinaryData* bytes,
                      protobuf_c_boolean* has_field, char* str) {
  if (str == NULL) {
    bytes->len = 0;
    bytes->data = NULL;
    *has_field = 0;
    return;
  }

  bytes->len = strlen(str);
  bytes->data = (uint8_t*) str;
  *has_field = 1;
}

/* Resort to some macro magic to make this somewhat cleaner. */
#define SET_BYTES(X, Y) SET_BYTES(&msg->X, &msg->has_ ## X, Y)

static void populate_log_entry(request_rec* r, LogEntry* msg) {
  SET_BYTES(remote_address, r->connection->remote_ip);
  SET_BYTES(local_address, r->connection->local_ip);
  SET_BYTES(remote_logname, (char*) ap_get_remote_logname(r));
  SET_BYTES(remote_user, r->user);
  SET_BYTES(filename, r->filename);
  SET_BYTES(unparsed_uri, r->unparsed_uri);
  SET_BYTES(method, (char*) r->method);
  SET_BYTES(protocol, (char*) r->protocol);

  msg->status = r->status;
  msg->has_status = 1;

  SET_BYTES(handler, (char*) r->handler);

  msg->has_bytes_sent = 1;
  msg->bytes_sent = r->bytes_sent;

  SET_BYTES(cookies, (char*) apr_table_get(r->headers_in, kCookieHeader));

  SET_BYTES(user_agent,
            (char*) apr_table_get(r->headers_in, kUserAgentHeader));

  SET_BYTES(virtual_host, r->server->server_hostname);
  SET_BYTES(server_name, (char*) ap_get_server_name(r));

  msg->request_time = r->request_time;
  msg->has_request_time = 1;

  SET_BYTES(referrer, (char*) apr_table_get(r->headers_in, kReferrerHeader));

  /* Try 'em both, just in case... */
  if (msg->referrer.len == 0) {
    SET_BYTES(referrer, (char*) apr_table_get(r->headers_in, kRefererHeader));
  }
}

/* Called by Apache for each transaction which needs to be logged. */
static int log_transaction(request_rec* r) {
  void* serialized_msg;
  unsigned long msg_len;

  LogEntry msg = LOG_ENTRY__INIT;
  populate_log_entry(r, &msg);

  msg_len = log_entry__get_packed_size(&msg);
  serialized_msg = malloc(msg_len);

  if (serialized_msg == NULL) {
    return DECLINED;
  }

  log_entry__pack(&msg, serialized_msg);
  write_serialized_msg(r, serialized_msg, msg_len);

  free(serialized_msg);
  return OK;
}

static void register_hooks(apr_pool_t* p) {
  ap_hook_open_logs(open_all_logs, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA protolog_module = {
  STANDARD20_MODULE_STUFF,            /* boilerplate             */
  NULL,                               /* per-dir config creator  */
  NULL,                               /* per-dir config merger   */
  create_config,                      /* server config creator   */
  merge_config,                       /* server config merger    */
  protolog_cmds,                      /* apr_table_t of commands */
  register_hooks                      /* register hooks          */
};
