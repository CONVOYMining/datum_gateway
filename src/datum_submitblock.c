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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <curl/curl.h>
#include <pthread.h>
#include <jansson.h>

#include "datum_utils.h"
#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_submitblock.h"

pthread_mutex_t submitblock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t submitblock_cond = PTHREAD_COND_INITIALIZER;
int submit_block_triggered = 0;
const char *submitblock_ptr = NULL;
bool submitblock_ptr_owned = false;
char submitblock_hash[256] = { 0 };

void preciousblock(CURL *curl, char *blockhash) {
	json_t *json;
	char rpc_data[384];
	
	snprintf(rpc_data, sizeof(rpc_data), "{\"method\":\"preciousblock\",\"params\":[\"%s\"],\"id\":1}", blockhash);
	json = bitcoind_json_rpc_call(curl, &datum_config, rpc_data);
	if (!json) return;
	
	json_decref(json);
	return;
}

datum_submitblock_status datum_submitblock_reply_status(const json_t *reply) {
	if (!reply) return DATUM_SUBMITBLOCK_UNKNOWN;
	const json_t * const result = json_object_get(reply, "result");
	if (json_is_null(result)) return DATUM_SUBMITBLOCK_ACCEPTED;
	if (json_is_string(result) && !strcmp(json_string_value(result), "duplicate")) return DATUM_SUBMITBLOCK_DUPLICATE;
	return DATUM_SUBMITBLOCK_REJECTED;
}

// Log what the node said about our block. Returns true when the block is in
// the node's chain, which includes "duplicate": the block is handed in twice,
// once inline from the share that found it and once from the submit thread,
// and the second copy is not a rejection.
bool datum_submitblock_log_reply(const json_t *reply, const char *block_hash_hex) {
	switch (datum_submitblock_reply_status(reply)) {
		case DATUM_SUBMITBLOCK_ACCEPTED:
			DLOG_INFO("Block %s submitted to upstream node successfully!", block_hash_hex);
			return true;
		case DATUM_SUBMITBLOCK_DUPLICATE:
			DLOG_INFO("Block %s was already accepted by the upstream node (duplicate submission)", block_hash_hex);
			return true;
		case DATUM_SUBMITBLOCK_UNKNOWN:
			// Didn't get a usable response at all: either the request never reached the node, or it
			// returned something we couldn't parse as a valid JSON-RPC reply, or a genuine top-level
			// JSON-RPC error occurred. In every case, we genuinely don't know whether the block was
			// accepted -- don't claim success.
			DLOG_ERROR("Did not get a valid response submitting block %s! It may or may not have been accepted -- check your node!", block_hash_hex);
			return false;
		case DATUM_SUBMITBLOCK_REJECTED:
		default: {
			char * const s = json_dumps(json_object_get(reply, "result"), JSON_ENCODE_ANY);
			DLOG_WARN("Upstream node rejected our block! (%s)", s ? s : "unknown");
			free(s);
			return false;
		}
	}
}

void datum_submitblock_doit(CURL *tcurl, char *url, const char *submitblock_req, const char *block_hash_hex) {
	json_t *r;
	// TODO: Move these types of things to the conf file
	if (!url) {
		r = bitcoind_json_rpc_call(tcurl, &datum_config, submitblock_req);
	} else {
		r = json_rpc_call(tcurl, url, NULL, submitblock_req);
	}
	datum_submitblock_log_reply(r, block_hash_hex);
	if (r) json_decref(r);
	
	// precious block!
	preciousblock(tcurl, submitblock_hash);
}

void *datum_submitblock_thread(void *ptr) {
	CURL *tcurl = NULL;
	int i;
	
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL for submitblock!!! This is REALLY REALLY BAD.  Like accidentally calling your wife your ex-girlfriend's name bad.");
		panic_from_thread(__LINE__);
	}
	
	DLOG_DEBUG("Submitblock thread active");
	
	while (1) {
		// Lock the mutex before waiting on the condition variable
		pthread_mutex_lock(&submitblock_mutex);
		
		// Wait for the event to be triggered
		while (!submit_block_triggered) {
			pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
		}
		
		if (submitblock_ptr != NULL) {
			DLOG_DEBUG("SUBMITTING BLOCK TO OUR NODE!");
			
			datum_submitblock_doit(tcurl,NULL,submitblock_ptr,submitblock_hash);
			
			if (datum_config.extra_block_submissions_count > 0) {
				for(i=0;i<datum_config.extra_block_submissions_count;i++) {
					DLOG_DEBUG("SUBMITTING BLOCK TO EXTRA NODE %d!",i+1);
					datum_submitblock_doit(tcurl,(char *)datum_config.extra_block_submissions_urls[i],submitblock_ptr,submitblock_hash);
				}
			}
			if (submitblock_ptr_owned) free((void *)submitblock_ptr);
			submitblock_ptr = NULL;
			submitblock_ptr_owned = false;
		}
		
		// Reset the event flag
		submit_block_triggered = 0;
		pthread_cond_broadcast(&submitblock_cond);
		
		// Unlock the mutex after processing
		pthread_mutex_unlock(&submitblock_mutex);
	}
	
	return NULL;
}

void datum_submitblock_waitfree(void) {
	pthread_mutex_lock(&submitblock_mutex);
	while (submit_block_triggered || submitblock_ptr != NULL) {
		pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
	}
	pthread_mutex_unlock(&submitblock_mutex);
}

static bool datum_submitblock_trigger_internal(
	const char *ptr, const char *hash, bool owned) {
	if (!ptr || !hash || strlen(hash) >= sizeof(submitblock_hash)) {
		DLOG_ERROR("Invalid block submission request");
		return false;
	}
	
	pthread_mutex_lock(&submitblock_mutex);
	while (submit_block_triggered || submitblock_ptr != NULL) {
		pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
	}
	submitblock_ptr = ptr;
	submitblock_ptr_owned = owned;
	strcpy(submitblock_hash, hash);
	submit_block_triggered = 1;
	pthread_cond_signal(&submitblock_cond);
	pthread_mutex_unlock(&submitblock_mutex);
	return true;
}

void datum_submitblock_trigger(const char *ptr, const char *hash) {
	datum_submitblock_trigger_internal(ptr, hash, false);
}

bool datum_submitblock_trigger_owned(char *ptr, const char *hash) {
	return datum_submitblock_trigger_internal(ptr, hash, true);
}


void datum_submitblock_init(void) {
	// TODO: Handle rare issues.
	pthread_t pthread_datum_submitblock_thread;
	pthread_create(&pthread_datum_submitblock_thread, NULL, datum_submitblock_thread, NULL);
	return;
}
