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
 * Copyright (c) 2026 Justin Filip and individual contributors
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

#include <errno.h>
#include <jansson.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "datum_submitblock.h"
#include "datum_utils.h"

extern pthread_mutex_t submitblock_mutex;
extern pthread_cond_t submitblock_cond;
extern int submit_block_triggered;
extern const char *submitblock_ptr;
extern char submitblock_hash[256];

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
	datum_submitblock_reply_tests();
}

static datum_submitblock_status status_of(const char * const json_text) {
	json_t * const reply = json_loads(json_text, 0, NULL);
	datum_test(reply != NULL);
	const datum_submitblock_status st = datum_submitblock_reply_status(reply);
	json_decref(reply);
	return st;
}

void datum_submitblock_reply_tests(void) {
	// No usable reply at all: the node may or may not have the block
	datum_test(datum_submitblock_reply_status(NULL) == DATUM_SUBMITBLOCK_UNKNOWN);
	
	// The null result the node sends on acceptance
	datum_test(status_of("{\"result\":null,\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_ACCEPTED);
	
	// Already have it and it is valid: the block is in the chain
	datum_test(status_of("{\"result\":\"duplicate\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_DUPLICATE);
	
	// Every other string is a rejection, including the other duplicate-* forms
	datum_test(status_of("{\"result\":\"duplicate-invalid\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"duplicate-inconclusive\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"inconclusive\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"bad-txnmrklroot\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"prev-blk-not-found\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	
	// A non-string or missing result is not something to call success
	datum_test(status_of("{\"result\":true,\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":{\"x\":1},\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
}
