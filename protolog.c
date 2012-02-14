// Apache module to emit log data in binary protocol buffer messages.
//
// Copyright (c) 2012, Rachel Kroll
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions 
// are met:
//    * Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above 
//      copyright notice, this list of conditions and the following 
//      disclaimer in the documentation and/or other materials provided 
//      with the distribution.
//    * Neither the name of Rachel Kroll nor the names of contributors 
//      may be used to endorse or promote products derived from this 
//      software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
// WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"                        /* for ap_get_remote_logname */
#include "http_log.h"
#include "http_protocol.h"
#include "util_time.h"

#include "apachelog.pb-c.h"

typedef struct {
  apr_file_t* log_handle;
} protolog_state;

/* XXX from config directive */
static const char* kLogFile = "/var/log/httpd/proto.log";

static int kLogFlags = APR_WRITE | APR_APPEND | APR_CREATE | APR_LARGEFILE;
static apr_fileperms_t kLogPerms = APR_OS_DEFAULT;

static const char* kCookieHeader = "Cookie";
static const char* kReferrerHeader = "Referrer";
static const char* kRefererHeader = "Referer";     /* sigh. */
static const char* kUserAgentHeader = "User-Agent";

module AP_MODULE_DECLARE_DATA protolog_module;

static void* make_protolog_state(apr_pool_t* p, server_rec* s) {
  protolog_state* pls;

  pls = (protolog_state*) apr_palloc(p, sizeof(protolog_state));

  return pls;
}

static int init_protolog(apr_pool_t* pc, apr_pool_t* p, apr_pool_t* pt,
                         server_rec* s) {
  protolog_state* pls = ap_get_module_config(s->module_config,
                                             &protolog_module);
  apr_file_t* fd;
  apr_status_t rv;

  rv = apr_file_open(&fd, kLogFile, kLogFlags, kLogPerms, p);

  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                 "could not open protocol binary log file %s", kLogFile);
    pls->log_handle = NULL;
    return DECLINED;
  }

  pls->log_handle = fd;
  return OK;
}

static void transmit_netstring(apr_file_t* handle, const char* protomsg,
                               unsigned long protomsg_len) {
  char preamble[16];
  char* netstring;
  size_t preamble_len;
  size_t netstring_len;

  snprintf(preamble, sizeof(preamble), "%lu:", protomsg_len);
  preamble_len = strlen(preamble);

  netstring_len = preamble_len + protomsg_len + 1;

  netstring = malloc(netstring_len);
  if (netstring == NULL) {
    return;
  }

  memcpy(&netstring[0], preamble, preamble_len);
  memcpy(&netstring[preamble_len], protomsg, protomsg_len);
  netstring[preamble_len + protomsg_len] = ',';

  apr_file_write(handle, netstring, &netstring_len);

  free(netstring);
}

static int push_log_message(request_rec* r) {
  void* serialized_msg;
  unsigned long msg_len;

  protolog_state* pls = ap_get_module_config(r->server->module_config,
                                             &protolog_module);
  if (!pls->log_handle) {
    return DECLINED;
  }

  LogEntry msg = LOG_ENTRY__INIT;
  msg.remote_address = r->connection->remote_ip;
  msg.local_address = r->connection->local_ip;
  msg.remote_logname = (char*) ap_get_remote_logname(r);
  msg.remote_user = r->user;
  msg.filename = r->filename;
  msg.unparsed_uri = r->unparsed_uri;
  msg.method = (char*) r->method;
  msg.protocol = r->protocol;

  msg.status = r->status;
  msg.has_status = 1;

  msg.handler = (char*) r->handler;

  msg.has_bytes_sent = 1;
  msg.bytes_sent = r->bytes_sent;

  msg.cookies = (char*) apr_table_get(r->headers_in, kCookieHeader);
  msg.user_agent = (char*) apr_table_get(r->headers_in, kUserAgentHeader);
  msg.virtual_host = r->server->server_hostname;
  msg.server_name = (char*) ap_get_server_name(r);

  msg.request_time = r->request_time;
  msg.has_request_time = 1;

  msg.referrer = (char*) apr_table_get(r->headers_in, kReferrerHeader);

  /* Try 'em both, just in case... */
  if (!msg.referrer) {
    msg.referrer = (char*) apr_table_get(r->headers_in, kRefererHeader);
  }

  msg_len = log_entry__get_packed_size(&msg);
  serialized_msg = malloc(msg_len);

  if (serialized_msg == NULL) {
    return DECLINED;
  }

  log_entry__pack(&msg, serialized_msg);
  transmit_netstring(pls->log_handle, serialized_msg, msg_len);

  free(serialized_msg);

  return OK;
}

static void register_hooks(apr_pool_t* p) {
  ap_hook_open_logs(init_protolog, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(push_log_message, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA protolog_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  make_protolog_state,
  NULL,
  NULL,
  register_hooks
};
