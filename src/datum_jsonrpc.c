/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of CONVOY's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://convoy.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2026 Bitcoin Ocean, LLC, Jason Hughes, and individual contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdbool.h>

#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb, void *user_data) {
	struct buf * const buf = user_data;
	size_t len;
	
	if (SIZE_MAX / size < nmemb) abort();
	len = size * nmemb;
	
	if (!buf_append(buf, ptr, len)) return 0;
	
	// NOTE: libcurl expects a different return value than write(2)
	return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb, void *user_data) {
	struct upload_buffer *ub = user_data;
	size_t len;
	if (SIZE_MAX / size < nmemb) nmemb = SIZE_MAX / size;
	len = size * nmemb;
	
	if (len > ub->len) len = ub->len;
	
	if (len) {
		memcpy(ptr, ub->buf, len);
		ub->buf = &((const char *)ub->buf)[len];
		ub->len -= len;
	}
	
	return len;
}

static
bool replace_curl_handle(CURL ** const curl) {
	assert(curl);
	curl_easy_cleanup(*curl);
	*curl = curl_easy_init();
	if (*curl) {
		DLOG_DEBUG("Reinitialized cURL handle after JSON-RPC failure");
		return true;
	}
	DLOG_ERROR("Could not reinitialize cURL after JSON-RPC failure");
	return false;
}

static
json_t *json_rpc_call_once(CURL ** const curl_handle, const char * const url, const char * const userpass, const char * const rpc_req, const char * const extra_header, long * const http_resp_code_out) {
	json_t *val, *err_val, *res_val;
	CURLcode rc;
	struct buf resp_buf = BUF_INIT;
	struct upload_buffer upload_data;
	json_error_t err = { };
	struct curl_slist *headers = NULL;
	char curl_err_str[CURL_ERROR_SIZE];
	bool check_for_result = true;
	assert(curl_handle);
	if (!*curl_handle && !replace_curl_handle(curl_handle)) return NULL;
	CURL * const curl = *curl_handle;
	
	curl_err_str[0] = '\0';
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_buf);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
	
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	
	upload_data.buf = rpc_req;
	upload_data.len = strlen(rpc_req);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)upload_data.len);
	
	headers = curl_slist_append(headers, "Content-type: application/json");
	headers = curl_slist_append(headers, "Expect:");
	
	if (extra_header) {
		headers = curl_slist_append(headers, extra_header);
		check_for_result = false;
	}
	
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
	rc = curl_easy_perform(curl);
	if (rc) {
		if (http_resp_code_out) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_resp_code_out);
		DLOG_DEBUG("json_rpc_call: HTTP request failed: %s", curl_err_str[0] ? curl_err_str : curl_easy_strerror(rc));
		DLOG_DEBUG("json_rpc_call: Request was: %s",rpc_req);
		goto err_out;
	}
	
	if (resp_buf.len && buf_nullterminate(&resp_buf)) {
		val = JSON_LOADS(resp_buf.s, &err);
	} else {
		DLOG_DEBUG("HTTP request returned 0 bytes");
		DLOG_DEBUG("Request was: %s", rpc_req);
		goto err_out;
	}
	if (!val) {
		DLOG_DEBUG("JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}
	
	if (check_for_result) {
		res_val = json_object_get(val, "result");
		err_val = json_object_get(val, "error");
		
		// A JSON-RPC reply's "result" being present-but-null is a legitimate, successful reply
		// (e.g. submitblock/preciousblock return null on success) -- it's the caller's job to
		// decide what a given method's result means, not ours. The only conditions that actually
		// indicate we didn't get a usable reply are: the "result" key being missing outright (a
		// non-compliant response), or a genuine non-null "error".
		const bool has_error = err_val && !json_is_null(err_val);
		const bool missing_result = !res_val;
		
		if (has_error || missing_result) {
			char *s;
			
			if (err_val) {
				s = json_dumps(err_val, JSON_INDENT(3));
			} else {
				s = strdup("(unknown reason)");
			}
			
			DLOG_DEBUG("JSON-RPC call failed: %s", s);
			
			free(s);
			json_decref(val);
			
			goto err_out;
		}
	}
	
	free(resp_buf.s);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	free(resp_buf.s);
	curl_slist_free_all(headers);
	replace_curl_handle(curl_handle);
	return NULL;
}

static
json_t *json_rpc_call_retry(CURL ** const curl, const char * const url, const char * const userpass, const char * const rpc_req, global_config_t * const cookie_cfg) {
	for (int attempt = 0; attempt < 2; ++attempt) {
		long http_resp_code = -1;
		json_t * const result = json_rpc_call_once(curl, url, userpass, rpc_req, NULL, &http_resp_code);
		if (result) return result;
		if (attempt) return NULL;
		if (cookie_cfg && !cookie_cfg->bitcoind_rpcuser[0] && http_resp_code == 401 && !update_rpc_cookie(cookie_cfg)) return NULL;
		DLOG_DEBUG("JSON-RPC request failed; retrying once with a fresh cURL handle");
	}
	return NULL;
}

json_t *json_rpc_call(CURL ** const curl, const char * const url, const char * const userpass, const char * const rpc_req) {
	return json_rpc_call_retry(curl, url, userpass, rpc_req, NULL);
}

bool update_rpc_cookie(global_config_t * const cfg) {
	assert(!cfg->bitcoind_rpcuser[0]);
	FILE * const F = fopen(cfg->bitcoind_rpccookiefile, "r");
	if (!F) {
		DLOG_ERROR("Cannot %s cookie file %s", "open", datum_config.bitcoind_rpccookiefile);
		return false;
	}
	if (!(fgets(cfg->bitcoind_rpcuserpass, sizeof(cfg->bitcoind_rpcuserpass), F) && cfg->bitcoind_rpcuserpass[0])) {
		DLOG_ERROR("Cannot %s cookie file %s", "read", datum_config.bitcoind_rpccookiefile);
		return false;
	}
	return true;
}

void update_rpc_auth(global_config_t * const cfg) {
	if (datum_config.bitcoind_rpccookiefile[0] && !cfg->bitcoind_rpcuser[0]) {
		update_rpc_cookie(cfg);
	} else {
		snprintf(datum_config.bitcoind_rpcuserpass, sizeof(datum_config.bitcoind_rpcuserpass), "%s:%s", datum_config.bitcoind_rpcuser, datum_config.bitcoind_rpcpassword);
	}
}

json_t *bitcoind_json_rpc_call(CURL ** const curl, global_config_t * const cfg, const char * const rpc_req) {
	return json_rpc_call_retry(curl, cfg->bitcoind_rpcurl, cfg->bitcoind_rpcuserpass, rpc_req, cfg);
}
