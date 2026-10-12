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
 * Copyright (c) 2026 Bitcoin Ocean, LLC, Jason Hughes, and individual contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

// Needed for INADDR_LOOPBACK on BSD
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define __BSD_VISIBLE 1
#endif

#include <arpa/inet.h>
#include <curl/curl.h>
#include <jansson.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "datum_jsonrpc.h"
#include "datum_utils.h"

typedef enum {
	DATUM_JSONRPC_TEST_CLOSE,
	DATUM_JSONRPC_TEST_SUCCESS,
} datum_jsonrpc_test_action;

typedef struct {
	int listen_fd;
	const datum_jsonrpc_test_action *actions;
	size_t action_count;
	size_t request_count;
} T_DATUM_JSONRPC_TEST_SERVER;

static bool jsonrpc_test_send_all(const int fd, const char *data, size_t len) {
	while (len) {
		const ssize_t sent = send(fd, data, len, MSG_NOSIGNAL);
		if (sent <= 0) return false;
		data += sent;
		len -= (size_t)sent;
	}
	return true;
}

static bool jsonrpc_test_read_request(const int fd) {
	char request[4096] = {0};
	size_t used = 0;
	while (used + 1 < sizeof(request)) {
		const ssize_t received = recv(fd, request + used, sizeof(request) - used - 1, 0);
		if (received <= 0) return false;
		used += (size_t)received;
		request[used] = 0;
		char * const body = strstr(request, "\r\n\r\n");
		char * const length = strstr(request, "Content-Length:");
		if (!body || !length) continue;
		unsigned long body_size = 0;
		if (sscanf(length, "Content-Length: %lu", &body_size) == 1 && used >= (size_t)(body + 4 - request) + body_size) return true;
	}
	return false;
}

static void *jsonrpc_test_server(void *arg) {
	T_DATUM_JSONRPC_TEST_SERVER * const server = arg;
	for (size_t i = 0; i < server->action_count; ++i) {
		struct pollfd listener = {
			.fd = server->listen_fd,
			.events = POLLIN,
		};
		if (poll(&listener, 1, 10000) <= 0) return NULL;
		const int client = accept(server->listen_fd, NULL, NULL);
		if (client < 0) return NULL;
		if (jsonrpc_test_read_request(client)) ++server->request_count;
		if (server->actions[i] == DATUM_JSONRPC_TEST_SUCCESS) {
			static const char response[] =
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: 32\r\n"
				"Connection: close\r\n\r\n"
				"{\"result\":7,\"error\":null,\"id\":1}";
			jsonrpc_test_send_all(client, response, sizeof(response) - 1);
		}
		shutdown(client, SHUT_RDWR);
		close(client);
	}
	return NULL;
}

static int jsonrpc_test_listener(uint16_t * const port) {
	const int listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) return -1;
	const int one = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	const struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) || listen(listener, 4)) {
		close(listener);
		return -1;
	}
	struct sockaddr_in bound;
	socklen_t bound_len = sizeof(bound);
	if (getsockname(listener, (struct sockaddr *)&bound, &bound_len)) {
		close(listener);
		return -1;
	}
	*port = ntohs(bound.sin_port);
	return listener;
}

static void jsonrpc_test_recovery(const datum_jsonrpc_test_action * const actions, const size_t action_count, const bool fail_first_call) {
	uint16_t port;
	T_DATUM_JSONRPC_TEST_SERVER server = {
		.listen_fd = jsonrpc_test_listener(&port),
		.actions = actions,
		.action_count = action_count,
	};
	datum_test(server.listen_fd >= 0);
	if (server.listen_fd < 0) return;
	pthread_t thread;
	const int thread_result = pthread_create(&thread, NULL, jsonrpc_test_server, &server);
	datum_test(thread_result == 0);
	if (thread_result) {
		close(server.listen_fd);
		return;
	}
	char url[64];
	snprintf(url, sizeof(url), "http://127.0.0.1:%u", port);
	CURL *curl = curl_easy_init();
	datum_test(curl != NULL);
	if (curl) {
		static const char request[] = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"test\",\"params\":[]}";
		if (fail_first_call) datum_test(json_rpc_call(&curl, url, NULL, request) == NULL);
		json_t * const response = json_rpc_call(&curl, url, NULL, request);
		datum_test(response != NULL);
		if (response) {
			datum_test(json_integer_value(json_object_get(response, "result")) == 7);
			json_decref(response);
		}
		curl_easy_cleanup(curl);
	}
	datum_test(!pthread_join(thread, NULL));
	datum_test(server.request_count == action_count);
	close(server.listen_fd);
}

void datum_jsonrpc_tests(void) {
	static const datum_jsonrpc_test_action retry_actions[] = {
		DATUM_JSONRPC_TEST_CLOSE,
		DATUM_JSONRPC_TEST_SUCCESS,
	};
	jsonrpc_test_recovery(retry_actions, sizeof(retry_actions) / sizeof(*retry_actions), false);
	static const datum_jsonrpc_test_action later_recovery_actions[] = {
		DATUM_JSONRPC_TEST_CLOSE,
		DATUM_JSONRPC_TEST_CLOSE,
		DATUM_JSONRPC_TEST_SUCCESS,
	};
	jsonrpc_test_recovery(later_recovery_actions, sizeof(later_recovery_actions) / sizeof(*later_recovery_actions), true);
}
