/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
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

pthread_mutex_t submitblock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t submitblock_cond = PTHREAD_COND_INITIALIZER;
int submit_block_triggered = 0;
const char *submitblock_ptr = NULL;
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

void datum_submitblock_doit(CURL *tcurl, char *url, const char *submitblock_req, const char *block_hash_hex) {
	json_t *r;
	char *s = NULL;
	// TODO: Move these types of things to the conf file
	if (!url) {
		r = bitcoind_json_rpc_call(tcurl, &datum_config, submitblock_req);
	} else {
		r = json_rpc_call(tcurl, url, NULL, submitblock_req);
	}
	if (!r) {
		// oddly, this means success here.
		DLOG_INFO("Block %s submitted to upstream node successfully!",block_hash_hex);
	} else {
		s = json_dumps(r, JSON_ENCODE_ANY);
		if (!s) {
			DLOG_WARN("Upstream node rejected our block! (unknown)");
		} else {
			DLOG_WARN("Upstream node rejected our block! (%s)",s);
			free(s);
		}
		json_decref(r);
	}
	
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
			submitblock_ptr = NULL;
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

void datum_submitblock_trigger(const char *ptr, const char *hash) {
	if (!ptr || !hash || strlen(hash) >= sizeof(submitblock_hash)) {
		DLOG_ERROR("Invalid block submission request");
		return;
	}
	
	pthread_mutex_lock(&submitblock_mutex);
	while (submit_block_triggered || submitblock_ptr != NULL) {
		pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
	}
	submitblock_ptr = ptr;
	strcpy(submitblock_hash, hash);
	submit_block_triggered = 1;
	pthread_cond_signal(&submitblock_cond);
	pthread_mutex_unlock(&submitblock_mutex);
}

typedef struct {
	const char *requests[2];
	char hashes[2][256];
	size_t consumed;
} T_DATUM_SUBMITBLOCK_TEST_STATE;

static void *datum_submitblock_test_consumer(void *ptr) {
	T_DATUM_SUBMITBLOCK_TEST_STATE *state = ptr;
	int i;
	
	usleep(10000);
	for(i=0;i<2;i++) {
		struct timespec deadline;
		pthread_mutex_lock(&submitblock_mutex);
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_sec++;
		while (!submit_block_triggered) {
			int wait_result = pthread_cond_timedwait(&submitblock_cond, &submitblock_mutex, &deadline);
			if (wait_result == ETIMEDOUT) {
				pthread_mutex_unlock(&submitblock_mutex);
				return NULL;
			}
			datum_test(wait_result == 0);
			if (wait_result != 0) {
				pthread_mutex_unlock(&submitblock_mutex);
				return NULL;
			}
		}
		
		state->requests[i] = submitblock_ptr;
		strcpy(state->hashes[i], submitblock_hash);
		state->consumed++;
		submitblock_ptr = NULL;
		submit_block_triggered = 0;
		pthread_cond_broadcast(&submitblock_cond);
		pthread_mutex_unlock(&submitblock_mutex);
	}
	return NULL;
}

void datum_submitblock_tests(void) {
	static const char first_request[] = "first block";
	static const char second_request[] = "second block";
	static const char first_hash[] = "00000001";
	static const char second_hash[] = "00000002";
	T_DATUM_SUBMITBLOCK_TEST_STATE state = {0};
	pthread_t consumer;
	int create_result;
	
	create_result = pthread_create(&consumer, NULL, datum_submitblock_test_consumer, &state);
	datum_test(create_result == 0);
	if (create_result != 0) return;
	datum_submitblock_trigger(first_request, first_hash);
	datum_submitblock_trigger(second_request, second_hash);
	datum_submitblock_waitfree();
	datum_test(pthread_join(consumer, NULL) == 0);
	datum_test(state.consumed == 2);
	datum_test(state.requests[0] == first_request);
	datum_test(state.requests[1] == second_request);
	datum_test(!strcmp(state.hashes[0], first_hash));
	datum_test(!strcmp(state.hashes[1], second_hash));
}

void datum_submitblock_init(void) {
	// TODO: Handle rare issues.
	pthread_t pthread_datum_submitblock_thread;
	pthread_create(&pthread_datum_submitblock_thread, NULL, datum_submitblock_thread, NULL);
	return;
}
