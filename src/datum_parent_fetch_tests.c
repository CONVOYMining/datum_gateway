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

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "datum_conf.h"
#include "datum_parent_fetch.h"
#include "datum_utils.h"

typedef struct {
	int listen_fd;
	bool saw_getblock;
	char expected_hash[65];
} T_DATUM_PARENT_FETCH_TEST_SERVER;

static pthread_mutex_t parent_test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t parent_test_cond = PTHREAD_COND_INITIALIZER;
static bool parent_test_replied;
static uint8_t parent_test_status;
static uint64_t parent_test_session_generation;
static uint8_t parent_test_block[3];
static size_t parent_test_block_size;

static bool parent_test_send_all(int fd, const char *data, size_t len) {
	while (len) {
		const ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
		if (n <= 0) return false;
		data += n;
		len -= (size_t)n;
	}
	return true;
}

static void *parent_test_server(void *arg) {
	T_DATUM_PARENT_FETCH_TEST_SERVER *server = arg;
	const int client = accept(server->listen_fd, NULL, NULL);
	if (client < 0) return NULL;
	char request[4096] = {0};
	size_t used = 0;
	while (used + 1 < sizeof(request)) {
		const ssize_t n = recv(client, request + used,
		                       sizeof(request) - used - 1, 0);
		if (n <= 0) break;
		used += (size_t)n;
		request[used] = 0;
		char *body = strstr(request, "\r\n\r\n");
		char *length = strstr(request, "Content-Length:");
		if (!body || !length) continue;
		unsigned long body_size = 0;
		if (sscanf(length, "Content-Length: %lu", &body_size) == 1 &&
		    used >= (size_t)(body + 4 - request) + body_size) break;
	}
	server->saw_getblock = strstr(request, "\"method\":\"getblock\"") &&
		strstr(request, server->expected_hash) && strstr(request, ",0]");
	const char body[] =
		"{\"result\":\"aabbcc\",\"error\":null,\"id\":\"datum-parent-fetch\"}";
	char response[512];
	const int response_size = snprintf(
		response, sizeof(response),
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
		"Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
		strlen(body), body);
	if (response_size > 0 && (size_t)response_size < sizeof(response)) {
		parent_test_send_all(client, response, (size_t)response_size);
	}
	close(client);
	return NULL;
}

static void parent_test_reply(
	uint8_t job_id, uint64_t session_generation, uint8_t status,
	const uint8_t parent_hash[32],
	const uint8_t *block, size_t block_size) {
	(void)job_id;
	(void)parent_hash;
	pthread_mutex_lock(&parent_test_lock);
	parent_test_status = status;
	parent_test_session_generation = session_generation;
	parent_test_block_size = block_size;
	if (block && block_size <= sizeof(parent_test_block)) {
		memcpy(parent_test_block, block, block_size);
	}
	parent_test_replied = true;
	pthread_cond_signal(&parent_test_cond);
	pthread_mutex_unlock(&parent_test_lock);
}

void datum_parent_fetch_tests(void) {
	const global_config_t saved_config = datum_config;
	parent_test_replied = false;
	parent_test_status = 0;
	parent_test_session_generation = 0;
	parent_test_block_size = 0;
	T_DATUM_PARENT_FETCH_TEST_SERVER server = {
		.listen_fd = socket(AF_INET, SOCK_STREAM, 0),
	};
	datum_test(server.listen_fd >= 0);
	if (server.listen_fd < 0) return;
	const struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	datum_test(!bind(server.listen_fd, (const struct sockaddr *)&address,
	                 sizeof(address)));
	datum_test(!listen(server.listen_fd, 1));
	struct sockaddr_in bound;
	socklen_t bound_len = sizeof(bound);
	datum_test(!getsockname(
		server.listen_fd, (struct sockaddr *)&bound, &bound_len));
	uint8_t parent_hash[32] = {0};
	parent_hash[0] = 1;
	memset(server.expected_hash, '0', 64);
	server.expected_hash[63] = '1';
	server.expected_hash[64] = 0;
	pthread_t server_thread;
	datum_test(!pthread_create(&server_thread, NULL, parent_test_server, &server));
	snprintf(datum_config.bitcoind_rpcurl, sizeof(datum_config.bitcoind_rpcurl),
	         "http://127.0.0.1:%u", ntohs(bound.sin_port));
	strcpy(datum_config.bitcoind_rpcuser, "test");
	strcpy(datum_config.bitcoind_rpcuserpass, "test:test");
	datum_test(!datum_parent_fetch_init(parent_test_reply));
	datum_test(datum_parent_fetch_enqueue(2, UINT64_C(0x1122334455667788), parent_hash) == DATUM_PARENT_FETCH_STATUS_QUEUED);
	
	pthread_mutex_lock(&parent_test_lock);
	struct timespec deadline;
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 5;
	while (!parent_test_replied) {
		if (pthread_cond_timedwait(
		        &parent_test_cond, &parent_test_lock, &deadline) == ETIMEDOUT) break;
	}
	pthread_mutex_unlock(&parent_test_lock);
	datum_test(parent_test_replied);
	datum_test(parent_test_status == DATUM_PARENT_FETCH_STATUS_SUCCESS);
	datum_test(parent_test_session_generation == UINT64_C(0x1122334455667788));
	datum_test(parent_test_block_size == 3);
	datum_test(!memcmp(parent_test_block, "\xaa\xbb\xcc", 3));
	pthread_join(server_thread, NULL);
	datum_test(server.saw_getblock);
	close(server.listen_fd);
	datum_config = saved_config;
}
