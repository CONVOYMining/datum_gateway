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
 * Copyright (c) 2026 Luke Dashjr
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

#include "datum_parent_fetch.h"

#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <jansson.h>

#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_logger.h"
#include "datum_utils.h"

#define DATUM_PARENT_FETCH_QUEUE_CAPACITY 2
#define DATUM_PARENT_FETCH_MAX_BLOCK_BYTES (4194304 - 42)

typedef struct {
	uint8_t job_id;
	uint64_t session_generation;
	uint8_t parent_hash[32];
} T_DATUM_PARENT_FETCH_REQUEST;

static pthread_mutex_t parent_fetch_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t parent_fetch_cond = PTHREAD_COND_INITIALIZER;
static T_DATUM_PARENT_FETCH_REQUEST parent_fetch_queue[DATUM_PARENT_FETCH_QUEUE_CAPACITY];
static size_t parent_fetch_queue_count;
static bool parent_fetch_started;
static datum_parent_fetch_reply_fn parent_fetch_reply;

static char *parent_fetch_rpc_hex(const uint8_t parent_hash[32]) {
	char *hex = malloc(65);
	if (!hex) return NULL;
	for (size_t i = 0; i < 32; ++i) {
		uchar_to_hex(hex + i * 2, parent_hash[31 - i]);
	}
	hex[64] = 0;
	return hex;
}

static char *parent_fetch_rpc_request(const uint8_t parent_hash[32]) {
	char *hex = parent_fetch_rpc_hex(parent_hash);
	if (!hex) return NULL;
	json_t *params = json_array();
	json_t *request = json_object();
	if (!params || !request ||
	    json_array_append_new(params, json_string(hex)) ||
	    json_array_append_new(params, json_integer(0)) ||
	    json_object_set_new(request, "jsonrpc", json_string("1.0")) ||
	    json_object_set_new(request, "id", json_string("datum-parent-fetch")) ||
	    json_object_set_new(request, "method", json_string("getblock")) ||
	    json_object_set_new(request, "params", params)) {
		if (request) json_decref(request);
		else if (params) json_decref(params);
		free(hex);
		return NULL;
	}
	free(hex);
	char *encoded = json_dumps(request, JSON_COMPACT);
	json_decref(request);
	return encoded;
}

static uint8_t parent_fetch_get(
	CURL * const curl, const T_DATUM_PARENT_FETCH_REQUEST * const request,
	uint8_t ** const block_out, size_t * const block_size_out) {
	char *rpc = parent_fetch_rpc_request(request->parent_hash);
	if (!rpc) return DATUM_PARENT_FETCH_STATUS_RPC_FAILED;
	json_t *response = bitcoind_json_rpc_call(curl, &datum_config, rpc);
	free(rpc);
	if (!response) return DATUM_PARENT_FETCH_STATUS_UNAVAILABLE;
	json_t *result = json_object_get(response, "result");
	const char *hex = json_string_value(result);
	const size_t hex_size = hex ? strlen(hex) : 0;
	if (!hex || !hex_size || (hex_size & 1) ||
	    hex_size / 2 > DATUM_PARENT_FETCH_MAX_BLOCK_BYTES) {
		json_decref(response);
		return DATUM_PARENT_FETCH_STATUS_RPC_FAILED;
	}
	for (size_t i = 0; i < hex_size; ++i) {
		if (!isxdigit((unsigned char)hex[i])) {
			json_decref(response);
			return DATUM_PARENT_FETCH_STATUS_RPC_FAILED;
		}
	}
	uint8_t *block = malloc(hex_size / 2);
	if (!block) {
		json_decref(response);
		return DATUM_PARENT_FETCH_STATUS_RPC_FAILED;
	}
	for (size_t i = 0; i < hex_size / 2; ++i) {
		block[i] = hex2bin_uchar(hex + i * 2);
	}
	*block_out = block;
	*block_size_out = hex_size / 2;
	json_decref(response);
	return DATUM_PARENT_FETCH_STATUS_SUCCESS;
}

static void *datum_parent_fetch_worker(void *unused) {
	CURL *curl = unused;
	for (;;) {
		pthread_mutex_lock(&parent_fetch_lock);
		while (!parent_fetch_queue_count) {
			pthread_cond_wait(&parent_fetch_cond, &parent_fetch_lock);
		}
		const T_DATUM_PARENT_FETCH_REQUEST request = parent_fetch_queue[0];
		--parent_fetch_queue_count;
		if (parent_fetch_queue_count) {
			memmove(parent_fetch_queue, parent_fetch_queue + 1,
			        parent_fetch_queue_count * sizeof(*parent_fetch_queue));
		}
		pthread_mutex_unlock(&parent_fetch_lock);
		
		uint8_t *block = NULL;
		size_t block_size = 0;
		const uint8_t status = parent_fetch_get(
			curl, &request, &block, &block_size);
		if (parent_fetch_reply) {
			parent_fetch_reply(request.job_id, request.session_generation, status,
				request.parent_hash, block, block_size);
		}
		free(block);
	}
	return NULL;
}

int datum_parent_fetch_init(const datum_parent_fetch_reply_fn reply) {
	pthread_mutex_lock(&parent_fetch_lock);
	if (parent_fetch_started) {
		parent_fetch_reply = reply;
		pthread_mutex_unlock(&parent_fetch_lock);
		return 0;
	}
	parent_fetch_reply = reply;
	CURL *curl = curl_easy_init();
	if (!curl) {
		pthread_mutex_unlock(&parent_fetch_lock);
		return -1;
	}
	pthread_t thread;
	if (pthread_create(&thread, NULL, datum_parent_fetch_worker, curl)) {
		curl_easy_cleanup(curl);
		pthread_mutex_unlock(&parent_fetch_lock);
		return -1;
	}
	pthread_detach(thread);
	parent_fetch_started = true;
	pthread_mutex_unlock(&parent_fetch_lock);
	return 0;
}

uint8_t datum_parent_fetch_enqueue(
	const uint8_t job_id, const uint64_t session_generation,
	const uint8_t parent_hash[32]) {
	pthread_mutex_lock(&parent_fetch_lock);
	if (!parent_fetch_started) {
		pthread_mutex_unlock(&parent_fetch_lock);
		return DATUM_PARENT_FETCH_STATUS_RPC_FAILED;
	}
	if (parent_fetch_queue_count == DATUM_PARENT_FETCH_QUEUE_CAPACITY) {
		pthread_mutex_unlock(&parent_fetch_lock);
		return DATUM_PARENT_FETCH_STATUS_BUSY;
	}
	T_DATUM_PARENT_FETCH_REQUEST *request = &parent_fetch_queue[parent_fetch_queue_count++];
	request->job_id = job_id;
	request->session_generation = session_generation;
	memcpy(request->parent_hash, parent_hash, 32);
	pthread_cond_signal(&parent_fetch_cond);
	pthread_mutex_unlock(&parent_fetch_lock);
	return DATUM_PARENT_FETCH_STATUS_QUEUED;
}
