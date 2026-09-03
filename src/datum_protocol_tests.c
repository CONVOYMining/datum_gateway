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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "datum_conf.h"
#include "datum_pow.h"
#include "datum_protocol_internal.h"
#include "datum_utils.h"

static void datum_protocol_config_v3_tests(void) {
	global_config_t saved_config = datum_config;
	const unsigned char saved_state = datum_state;
	const int saved_client_active = atomic_load(&datum_protocol_client_active);
	unsigned char payload[128] = {0};
	size_t i = 0;
	
	payload[i++] = 3;
	payload[i++] = 1;
	payload[i++] = 0x51;
	pk_u64le(payload, i, UINT64_C(0x887766555d965e4e)); i += 8;
	pk_u64le(payload, i, UINT64_C(0x887766555d965e4e));
	memset(payload + i + 8, 0x5a, 32);
	i += 40;
	payload[i++] = 3;
	memcpy(payload + i, "tag", 3); i += 3;
	pk_u64le(payload, i, 1024); i += 8;
	const size_t config_flags = i;
	payload[i++] = 0;
	payload[i++] = 0xFE;
	datum_state = 3;
	atomic_store(&datum_protocol_client_active, 3);
	datum_test(datum_protocol_client_configure((int)i, payload));
	datum_test(datum_config.prime_id == UINT64_C(0x887766555d965e4e));
	datum_test(datum_config.override_mining_pool_scriptpubkey_len == 1);
	datum_test(datum_config.override_mining_pool_scriptpubkey[0] == 0x51);
	datum_test(!strcmp(datum_config.override_mining_coinbase_tag_primary, "tag"));
	datum_test(datum_config.override_vardiff_min == 1024);
	datum_test(!datum_protocol_is_active());
	unsigned char notice[36] = {
		DATUM_ABW_DRAFT_REVISION, DATUM_ABW_ASSIGNMENT_ACTIVE, 0,
	};
	memset(notice + 3, 0x5a, 32);
	notice[35] = 0xFE;
	datum_test(datum_protocol_abw_assignment_notice(sizeof(notice), notice));
	datum_test(datum_protocol_is_active());
	T_DATUM_TEMPLATE_DATA block_template = {0};
	datum_test(datum_protocol_abw_apply_active(&block_template));
	payload[0] = 2;
	datum_test(!datum_protocol_client_configure((int)i, payload));
	payload[0] = 3;
	payload[config_flags] = DATUM_CONFIG_FLAG_ABW_DISABLED;
	datum_test(datum_protocol_client_configure((int)i, payload));
	datum_test(!datum_protocol_abw_required());
	datum_test(datum_protocol_is_active());
	memset(&block_template, 0, sizeof(block_template));
	datum_test(!datum_protocol_abw_apply_active(&block_template));
	payload[config_flags] = 0;
	datum_test(datum_protocol_client_configure((int)i, payload));
	datum_test(datum_protocol_abw_required());
	datum_test(!datum_protocol_is_active());
	datum_test(datum_protocol_abw_assignment_notice(sizeof(notice), notice));
	datum_test(datum_protocol_is_active());
	payload[config_flags] = 0x80;
	datum_test(!datum_protocol_client_configure((int)i, payload));
	datum_protocol_abw_reset();
	datum_config = saved_config;
	datum_state = saved_state;
	atomic_store(&datum_protocol_client_active, saved_client_active);
}

static size_t datum_protocol_test_flush_read(int sender, int receiver,
	unsigned char *output, size_t output_size) {
	const size_t expected = (size_t)server_out_buf;
	if (expected > output_size) return 0;
	size_t received = 0;
	for (unsigned int attempt = 0; attempt < 10000 &&
	     (server_out_buf || received < expected); ++attempt) {
		if (datum_protocol_flush_socket(sender)) return 0;
		const ssize_t count = recv(receiver, output + received,
			output_size - received, MSG_DONTWAIT);
		if (count > 0) received += (size_t)count;
		else if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
			errno != EINTR) return 0;
		if (server_out_buf || received < expected) usleep(100);
	}
	return received == expected ? received : 0;
}

static int datum_protocol_test_decrypt_frame(const unsigned char *wire,
	size_t wire_size, size_t *offset, uint32_t *header_key,
	unsigned char nonce[crypto_box_NONCEBYTES],
	T_DATUM_PROTOCOL_HEADER *header, unsigned char *clear,
	size_t clear_size) {
	if (*offset + sizeof(*header) > wire_size) return -1;
	memcpy(header, wire + *offset, sizeof(*header));
	*((uint32_t *)header) ^= *header_key;
	*header_key = datum_header_xor_feedback(*header_key);
	*offset += sizeof(*header);
	if (!header->is_encrypted_channel || header->cmd_len < crypto_box_MACBYTES ||
	    *offset + header->cmd_len > wire_size ||
	    header->cmd_len - crypto_box_MACBYTES > clear_size) return -1;
	if (crypto_box_open_easy_afternm(clear, wire + *offset, header->cmd_len,
		nonce, session_precomp.precomp_remote)) return -1;
	*offset += header->cmd_len;
	datum_increment_session_nonce(nonce);
	return header->cmd_len - crypto_box_MACBYTES;
}

static void datum_protocol_bulk_tests(void) {
	const bool saved_enabled = atomic_load(&datum_protocol_bulk_enabled);
	const int saved_out = server_out_buf;
	const uint32_t saved_header_key = sending_header_key;
	unsigned char saved_nonce[sizeof(session_nonce_sender)];
	memcpy(saved_nonce, session_nonce_sender, sizeof(saved_nonce));
	unsigned char *saved_output = NULL;
	if (saved_out > 0) {
		saved_output = malloc((size_t)saved_out);
		if (saved_output)
			memcpy(saved_output, server_send_buffer, (size_t)saved_out);
	}
	
	datum_protocol_bulk_reset();
	atomic_store(&datum_protocol_bulk_enabled, true);
	server_out_buf = 0;
	const size_t payload_size = DATUM_PROTOCOL_MAX_CMD_DATA_SIZE - 1024;
	unsigned char *payload = malloc(payload_size);
	int sockets[2] = {-1, -1};
	const int socket_result = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
	datum_test(datum_socket_set_nonblock(sockets[0]));
	datum_test(datum_socket_set_nonblock(sockets[1]));
	datum_test(payload != NULL);
	datum_test(socket_result == 0);
	if (!payload || socket_result) goto cleanup;
	for (size_t i = 0; i < payload_size; ++i) {
		payload[i] = (unsigned char)(i * 131U + 17U);
	}
	datum_test(datum_protocol_bulk_cmd(payload, (int)payload_size) == 0);
	datum_test(datum_protocol_bulk_cmd_for_session(
		payload, (int)payload_size,
		atomic_load(&datum_session_generation) + 1) == -1);
	
	uint32_t receiver_header_key = sending_header_key;
	unsigned char receiver_nonce[crypto_box_NONCEBYTES];
	memcpy(receiver_nonce, session_nonce_sender, sizeof(receiver_nonce));
	unsigned char wire[2 * (sizeof(T_DATUM_PROTOCOL_HEADER) +
		DATUM_BULK_FRAGMENT_HEADER_SIZE + DATUM_BULK_FRAGMENT_DATA_SIZE +
		crypto_box_MACBYTES)];
	unsigned char clear[DATUM_BULK_FRAGMENT_HEADER_SIZE +
		DATUM_BULK_FRAGMENT_DATA_SIZE];
	const unsigned char share[] = {0x27, 'S', 'H', 'A', 'R', 'E'};
	const unsigned char block[] = {0x27, 'B', 'L', 'O', 'C', 'K'};
	bool share_sent = false;
	bool block_sent = false;
	uint32_t bulk_id = 0;
	uint32_t verified_offset = 0;
	while (verified_offset < payload_size) {
		bool expect_share = false;
		bool expect_block = false;
		if (!share_sent) {
			datum_test(datum_protocol_mining_cmd(
				(void *)share, sizeof(share)) == 0);
			datum_protocol_bulk_drain_one();
			share_sent = expect_share = true;
		} else {
			datum_protocol_bulk_drain_one();
			if (!block_sent && verified_offset >=
			    payload_size / 2) {
				datum_test(datum_protocol_mining_cmd(
					(void *)block, sizeof(block)) == 0);
				block_sent = expect_block = true;
			}
		}
		
		const size_t wire_size = datum_protocol_test_flush_read(
			sockets[0], sockets[1], wire, sizeof(wire));
		datum_test(wire_size != 0);
		if (!wire_size) break;
		size_t wire_offset = 0;
		bool saw_fragment = false;
		bool saw_share = false;
		bool saw_block = false;
		while (wire_offset < wire_size) {
			T_DATUM_PROTOCOL_HEADER header;
			const int clear_size = datum_protocol_test_decrypt_frame(
				wire, wire_size, &wire_offset, &receiver_header_key,
				receiver_nonce, &header, clear, sizeof(clear));
			datum_test(clear_size >= 0);
			if (clear_size < 0) break;
			if (header.proto_cmd == 5) {
				if ((size_t)clear_size == sizeof(share) &&
				    !memcmp(clear, share, sizeof(share))) saw_share = true;
				if ((size_t)clear_size == sizeof(block) &&
				    !memcmp(clear, block, sizeof(block))) saw_block = true;
				continue;
			}
			datum_test(header.proto_cmd == 6);
			datum_test((size_t)clear_size > DATUM_BULK_FRAGMENT_HEADER_SIZE);
			datum_test(!memcmp(clear, "DBF\x01", 4));
			if (bulk_id) datum_test(upk_u32le(clear, 4) == bulk_id);
			else bulk_id = upk_u32le(clear, 4);
			datum_test(upk_u32le(clear, 8) == payload_size);
			const uint32_t fragment_offset = upk_u32le(clear, 12);
			const uint32_t fragment_size = (uint32_t)clear_size -
				DATUM_BULK_FRAGMENT_HEADER_SIZE;
			datum_test(fragment_offset == verified_offset);
			datum_test(!memcmp(clear + DATUM_BULK_FRAGMENT_HEADER_SIZE,
				payload + fragment_offset, fragment_size));
			verified_offset += fragment_size;
			saw_fragment = true;
		}
		datum_test(saw_share == expect_share);
		datum_test(saw_block == expect_block);
		if (expect_share) datum_test(!saw_fragment);
		if (expect_block) datum_test(saw_fragment);
		if (saw_fragment) {
			unsigned char ack[12] = {'D', 'B', 'A', 1};
			pk_u32le(ack, 4, bulk_id);
			pk_u32le(ack, 8, verified_offset);
			datum_test(datum_protocol_bulk_ack(sizeof(ack), ack));
		}
	}
	datum_test(verified_offset == payload_size);
	datum_test(share_sent && block_sent);
	
	// A disconnect abandons an incomplete transfer without delaying the next
	// session's primary mining traffic.
	datum_test(datum_protocol_bulk_cmd(payload, (int)payload_size) == 0);
	datum_protocol_bulk_drain_one();
	datum_test(datum_protocol_test_flush_read(sockets[0], sockets[1], wire, sizeof(wire)) != 0);
	close(sockets[0]); sockets[0] = -1;
	close(sockets[1]); sockets[1] = -1;
	datum_protocol_bulk_reset();
	datum_test(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	datum_test(datum_socket_set_nonblock(sockets[0]));
	datum_test(datum_socket_set_nonblock(sockets[1]));
	receiver_header_key = sending_header_key;
	memcpy(receiver_nonce, session_nonce_sender, sizeof(receiver_nonce));
	datum_test(datum_protocol_mining_cmd((void *)share, sizeof(share)) == 0);
	const size_t resumed_size = datum_protocol_test_flush_read(sockets[0], sockets[1], wire, sizeof(wire));
	size_t resumed_offset = 0;
	T_DATUM_PROTOCOL_HEADER resumed_header;
	const int resumed_clear_size = datum_protocol_test_decrypt_frame(
		wire, resumed_size, &resumed_offset, &receiver_header_key,
		receiver_nonce, &resumed_header, clear, sizeof(clear));
	datum_test(resumed_header.proto_cmd == 5);
	datum_test(resumed_clear_size == sizeof(share));
	datum_test(!memcmp(clear, share, sizeof(share)));
	
	// Until Apex advertises DBF support, retain the legacy command-5 reply.
	atomic_store(&datum_protocol_bulk_enabled, false);
	const size_t fallback_size = DATUM_BULK_FRAGMENT_DATA_SIZE + 8;
	datum_test(datum_protocol_bulk_cmd(payload, (int)fallback_size) == 0);
	const size_t fallback_wire_size = datum_protocol_test_flush_read(sockets[0], sockets[1], wire, sizeof(wire));
	size_t fallback_wire_offset = 0;
	T_DATUM_PROTOCOL_HEADER fallback_header;
	const int fallback_clear_size = datum_protocol_test_decrypt_frame(
		wire, fallback_wire_size, &fallback_wire_offset,
		&receiver_header_key, receiver_nonce, &fallback_header, clear,
		sizeof(clear));
	datum_test(fallback_header.proto_cmd == 5);
	datum_test(fallback_clear_size == (int)fallback_size);
	datum_test(!memcmp(clear, payload, fallback_size));
	datum_test(fallback_wire_offset == fallback_wire_size);
	
cleanup:
	if (sockets[0] >= 0) close(sockets[0]);
	if (sockets[1] >= 0) close(sockets[1]);
	free(payload);
	datum_protocol_bulk_reset();
	atomic_store(&datum_protocol_bulk_enabled, saved_enabled);
	server_out_buf = saved_out;
	if (saved_output) {
		memcpy(server_send_buffer, saved_output, (size_t)saved_out);
		free(saved_output);
	}
	sending_header_key = saved_header_key;
	memcpy(session_nonce_sender, saved_nonce, sizeof(saved_nonce));
}


static void datum_protocol_resume_tests(void) {
	T_DATUM_PROTOCOL_POW pow = {0};
	const unsigned char message[] = {0x27, 0xFE};
	
	datum_protocol_replay_clear();
	pow.nonce = UINT64_C(0x100000009);
	pow.target_byte = 10;
	pow.datum_job_id = 3;
	datum_test(datum_protocol_replay_add(&pow, message, sizeof(message)) != NULL);
	datum_test(datum_replay_count == 1);
	datum_protocol_replay_mark_responded_legacy(8, 10, 3);
	datum_test(datum_replay_count == 1);
	datum_protocol_replay_mark_responded_legacy(9, 10, 3);
	datum_test(datum_replay_count == 0);
	
	datum_test(datum_protocol_replay_add(&pow, message, sizeof(message)) != NULL);
	pow.nonce = UINT64_C(0x200000009);
	datum_test(datum_protocol_replay_add(&pow, message, sizeof(message)) != NULL);
	datum_protocol_replay_mark_responded_legacy(9, 10, 3);
	datum_test(datum_replay_count == 2);
	datum_protocol_replay_clear();
	
	unsigned char backpressure_message[32] = {0x27, 0xFE};
	unsigned char backpressure_before[sizeof(backpressure_message)];
	unsigned char nonce_before[sizeof(session_nonce_sender)];
	memcpy(backpressure_before, backpressure_message,
		sizeof(backpressure_message));
	memcpy(nonce_before, session_nonce_sender, sizeof(nonce_before));
	const uint32_t header_key_before = sending_header_key;
	const int buffered_before = server_out_buf;
	server_out_buf = DATUM_PROTOCOL_BUFFER_SIZE - 1;
	datum_test(datum_protocol_mining_cmd(backpressure_message, 2) == -1);
	datum_test(sending_header_key == header_key_before);
	datum_test(!memcmp(session_nonce_sender, nonce_before, sizeof(nonce_before)));
	datum_test(!memcmp(backpressure_message, backpressure_before,
		sizeof(backpressure_message)));
	datum_test(server_out_buf == DATUM_PROTOCOL_BUFFER_SIZE - 1);
	server_out_buf = buffered_before;
	
	const uint64_t current_generation = atomic_load(&datum_session_generation);
	datum_test(datum_protocol_mining_cmd_for_session(
		backpressure_message, 2, current_generation + 1) == -1);
	datum_test(sending_header_key == header_key_before);
	datum_test(!memcmp(session_nonce_sender, nonce_before, sizeof(nonce_before)));
	datum_test(server_out_buf == buffered_before);
}

static void datum_protocol_migration_tests(void) {
	global_config_t saved_config = datum_config;
	unsigned char payload[192] = {0};
	unsigned char command[193] = {0xA4};
	unsigned char home_payload[192] = {0};
	T_DATUM_PROTOCOL_HEADER header = {0};
	char endpoint[sizeof(datum_config.datum_pool_host)];
	char endpoint_pubkey[sizeof(datum_config.datum_pool_pubkey)];
	char configured_pubkey[129];
	char migrated_pubkey[129];
	const char host[] = "next.pool.example";
	const unsigned char return_home[] = {0, 1, 0xFE};
	int port;
	size_t i = 0;
	size_t key_offset;
	size_t home_i = 0;
	
	for (size_t j = 0; j < 32; ++j) {
		uchar_to_hex(configured_pubkey + j * 2, j);
		uchar_to_hex(configured_pubkey + 64 + j * 2, 32 + j);
	}
	configured_pubkey[128] = '\0';
	strcpy(datum_config.datum_pool_host, "configured.pool.example");
	datum_config.datum_pool_port = 28915;
	strcpy(datum_config.datum_pool_pubkey, configured_pubkey);
	datum_config.datum_pool_migration_host[0] = '\0';
	datum_config.datum_pool_migration_port = 0;
	datum_config.datum_pool_migration_pubkey[0] = '\0';
	datum_config.datum_pool_migration_deadline_ms = 0;
	datum_config.datum_pool_migration_max_seconds = 86400;
	
	payload[i++] = 0; // revision
	payload[i++] = 0; // migrate
	pk_u16le(payload, i, sizeof(host) - 1); i += 2;
	memcpy(payload + i, host, sizeof(host) - 1); i += sizeof(host) - 1;
	pk_u16le(payload, i, 29634); i += 2;
	key_offset = i;
	for (size_t j = 0; j < 64; ++j) payload[i++] = j;
	payload[i++] = 0xFE;
	memcpy(command + 1, payload, i);
	header.cmd_len = i + 1;
	
	datum_test(datum_protocol_mining_cmd5(&header, command) == 0);
	datum_test(!datum_config.datum_pool_migration_host[0]);
	header.is_signed = true;
	datum_test(datum_protocol_mining_cmd5(&header, command) == -1);
	datum_test(!strcmp(datum_config.datum_pool_host, "configured.pool.example"));
	datum_test(datum_config.datum_pool_port == 28915);
	datum_test(!strcmp(datum_config.datum_pool_migration_host, host));
	datum_test(datum_config.datum_pool_migration_port == 29634);
	datum_test(!strcmp(datum_config.datum_pool_migration_pubkey, configured_pubkey));
	datum_test(datum_config.datum_pool_migration_deadline_ms > current_time_millis());
	
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, host));
	datum_test(port == 29634);
	datum_test(!strcmp(endpoint_pubkey, configured_pubkey));
	datum_test(!datum_config.datum_pool_migration_host[0]);
	datum_test(datum_config.datum_pool_migration_port == 0);
	datum_test(!datum_config.datum_pool_migration_pubkey[0]);
	datum_test(datum_config.datum_pool_migration_deadline_ms == 0);
	datum_test(!datum_protocol_migration_expired(current_time_millis()));
	
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, "configured.pool.example"));
	datum_test(port == 28915);
	datum_test(!strcmp(endpoint_pubkey, configured_pubkey));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	datum_test(datum_protocol_migration_request(
		(int)sizeof(return_home), return_home) == 1);
	
	for (size_t j = 0; j < 64; ++j) {
		payload[key_offset + j] = 0x80 + j;
		uchar_to_hex(migrated_pubkey + j * 2, 0x80 + j);
	}
	migrated_pubkey[128] = '\0';
	datum_test(datum_protocol_migration_request((int)i, payload) == -1);
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint_pubkey, migrated_pubkey));
	datum_config.datum_pool_migration_max_seconds = 0;
	datum_test(datum_protocol_migration_request(
		(int)sizeof(return_home), return_home) == 1);
	datum_test(datum_protocol_migration_expired(UINT64_MAX));
	datum_config.datum_pool_migration_max_seconds = 86400;
	datum_test(datum_protocol_migration_request(
		(int)sizeof(return_home), return_home) == -1);
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, datum_config.datum_pool_host));
	datum_test(port == datum_config.datum_pool_port);
	datum_test(!strcmp(endpoint_pubkey, datum_config.datum_pool_pubkey));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	
	datum_config.datum_pool_migration_max_seconds = 0;
	datum_test(datum_protocol_migration_request((int)i, payload) == 1);
	datum_test(!datum_config.datum_pool_migration_host[0]);
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, datum_config.datum_pool_host));
	datum_test(port == datum_config.datum_pool_port);
	datum_test(!strcmp(endpoint_pubkey, datum_config.datum_pool_pubkey));
	datum_config.datum_pool_migration_max_seconds = 86400;
	
	datum_test(datum_protocol_migration_request((int)i, payload) == -1);
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	
	home_payload[home_i++] = 0; // revision
	home_payload[home_i++] = 0; // migrate
	pk_u16le(home_payload, home_i, strlen(datum_config.datum_pool_host)); home_i += 2;
	memcpy(home_payload + home_i, datum_config.datum_pool_host,
		strlen(datum_config.datum_pool_host));
	home_i += strlen(datum_config.datum_pool_host);
	pk_u16le(home_payload, home_i, datum_config.datum_pool_port); home_i += 2;
	for (size_t j = 0; j < 64; ++j) home_payload[home_i++] = j;
	home_payload[home_i++] = 0xFE;
	datum_test(datum_protocol_migration_request((int)home_i, home_payload) == -1);
	datum_test(datum_config.datum_pool_migration_deadline_ms == 0);
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, datum_config.datum_pool_host));
	datum_test(port == datum_config.datum_pool_port);
	datum_test(!strcmp(endpoint_pubkey, datum_config.datum_pool_pubkey));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	datum_test(datum_protocol_migration_request((int)home_i, home_payload) == 1);
	
	datum_config.datum_pool_migration_host[0] = 'x';
	datum_config.datum_pool_migration_host[1] = '\0';
	datum_config.datum_pool_migration_port = 1;
	strcpy(datum_config.datum_pool_migration_pubkey, configured_pubkey);
	datum_config.datum_pool_migration_deadline_ms = current_time_millis() - 1;
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(datum_protocol_migration_expired(current_time_millis()));
	datum_test(datum_protocol_migration_request((int)i, payload) == -1);
	datum_test(!datum_config.datum_pool_migration_host[0]);
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	
	payload[0] = 1;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	payload[0] = 0;
	payload[1] = 2;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	payload[1] = 0;
	payload[i - 1] = 0;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	pk_u16le(payload, 4 + sizeof(host) - 1, 0);
	payload[i - 1] = 0xFE;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	
	datum_config = saved_config;
}

static void datum_protocol_abw_cache_tests(void) {
	unsigned char xor_key[16];
	unsigned char key_hash[32];
	unsigned char raw_hash[32];
	unsigned char coinbase[16] = {1, 0, 0, 0, 1};
	T_DATUM_TEMPLATE_DATA block_template = {0};
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_PROTOCOL_POW pow = {0};
	for (size_t i = 0; i < sizeof(xor_key); ++i) {
		xor_key[i] = (unsigned char)(i + 1);
	}
	memset(raw_hash, 0xff, sizeof(raw_hash));
	datum_test(datum_blake2b_xor_key_hash(key_hash, xor_key));
	
	unsigned char reveal[19] = {DATUM_ABW_DRAFT_REVISION, 3};
	memcpy(reveal + 2, xor_key, sizeof(xor_key));
	reveal[18] = 0xFE;
	unsigned char notice[36] = {
		DATUM_ABW_DRAFT_REVISION, 0, 3,
	};
	memcpy(notice + 3, key_hash, sizeof(key_hash));
	notice[35] = 0xFE;
	unsigned char activation[3] = {DATUM_ABW_DRAFT_REVISION, 3, 0xFE};
	
	datum_protocol_abw_reset();
	datum_protocol_replay_clear();
	datum_test(datum_protocol_abw_reveal(sizeof(reveal), reveal));
	datum_test(datum_protocol_abw_assignment_notice(sizeof(notice), notice));
	datum_test(datum_protocol_abw_assignment_notice(sizeof(notice), notice));
	unsigned char conflicting_notice[sizeof(notice)];
	memcpy(conflicting_notice, notice, sizeof(notice));
	conflicting_notice[3] ^= 1;
	datum_test(!datum_protocol_abw_assignment_notice(sizeof(conflicting_notice), conflicting_notice));
	datum_test(!datum_protocol_abw_apply_active(&block_template));
	datum_test(datum_protocol_abw_activation(sizeof(activation), activation));
	datum_test(datum_protocol_abw_apply_active(&block_template));
	datum_test(block_template.abw_assignment_id == 4);
	datum_test(!memcmp(block_template.xor_key_hash, key_hash, 32));
	
	block_template.version = UINT32_C(0x20000000);
	block_template.height = 42;
	block_template.bits_uint = UINT32_C(0x1d00ffff);
	job.block_template = &block_template;
	job.version_uint = block_template.version;
	job.height = block_template.height;
	job.nbits_uint = block_template.bits_uint;
	job.target_pot_index = 4;
	job.blake2b_time_on_wire = 1000;
	pow.sjob = &job;
	pow.datum_job_id = 2;
	pow.abw_assignment_id = 4;
	pow.target_byte = 10;
	pow.nonce = 7;
	pow.ntime = 1000;
	datum_test(datum_protocol_abw_cache_candidate(&pow, coinbase, sizeof(coinbase), raw_hash));
	
	datum_config.mining_abw_verify_all_shares_on_disclosure = true;
	unsigned char receipt[35] = {DATUM_ABW_DRAFT_REVISION, 3};
	memcpy(receipt + 2, raw_hash, sizeof(raw_hash));
	receipt[34] = 0xFE;
	datum_test(datum_protocol_abw_candidate_receipt(sizeof(receipt), receipt));
	datum_test(datum_protocol_abw_candidate_release(sizeof(receipt), receipt));
	
	unsigned char second_hash[32];
	memset(second_hash, 0xfe, sizeof(second_hash));
	pow.nonce++;
	datum_test(datum_protocol_abw_cache_candidate(&pow, coinbase, sizeof(coinbase), second_hash));
	datum_config.mining_abw_verify_all_shares_on_disclosure = false;
	memcpy(pow.raw_pow_hash, second_hash, sizeof(pow.raw_pow_hash));
	static const unsigned char replay_message[] = {0x27, 0xFE};
	datum_test(datum_protocol_replay_add(&pow, replay_message, sizeof(replay_message)) != NULL);
	const size_t replay_count_before = datum_replay_count;
	unsigned char response[44] = {DATUM_POW_SHARE_RESPONSE_ACCEPTED};
	pk_u32le(response, 3, (uint32_t)pow.nonce);
	response[7] = pow.target_byte;
	response[8] = pow.datum_job_id;
	response[9] = 0x06;
	response[10] = 3;
	memcpy(response + 11, second_hash, sizeof(second_hash));
	response[43] = 0xFE;
	datum_test(datum_protocol_share_response(sizeof(response), response));
	datum_test(datum_replay_count + 1 == replay_count_before);
	datum_config.mining_abw_verify_all_shares_on_disclosure = true;
	
	unsigned char subsidy_hash[32];
	memset(subsidy_hash, 0xfc, sizeof(subsidy_hash));
	pow.subsidy_only = true;
	pow.nonce++;
	datum_test(datum_protocol_abw_cache_candidate(&pow, coinbase, sizeof(coinbase), subsidy_hash));
	pow.subsidy_only = false;
	
	datum_test(datum_protocol_abw_reveal(sizeof(reveal), reveal));
	datum_test(datum_protocol_abw_assignment_revealed(4));
	datum_test(!datum_protocol_abw_cache_candidate(&pow, coinbase, sizeof(coinbase), raw_hash));
	reveal[18] = 0;
	datum_test(!datum_protocol_abw_reveal(sizeof(reveal), reveal));
	reveal[18] = 0xFE;
	notice[3] ^= 1;
	datum_test(datum_protocol_abw_assignment_notice(sizeof(notice), notice));
	datum_protocol_abw_reset();
	datum_protocol_replay_clear();
}

static void datum_pow_response_large_difficulty_test(void) {
	unsigned char accepted[9] = {DATUM_POW_SHARE_RESPONSE_ACCEPTED};
	unsigned char rejected[9] = {DATUM_POW_SHARE_RESPONSE_REJECTED};
	const uint64_t saved_accepted_count = datum_accepted_share_count;
	const uint64_t saved_accepted_diff = datum_accepted_share_diff;
	const uint64_t saved_rejected_count = datum_rejected_share_count;
	const uint64_t saved_rejected_diff = datum_rejected_share_diff;
	
	accepted[7] = 40;
	rejected[7] = 40;
	datum_accepted_share_count = 0;
	datum_accepted_share_diff = 0;
	datum_rejected_share_count = 0;
	datum_rejected_share_diff = 0;
	datum_test(datum_protocol_share_response(sizeof(accepted), accepted));
	datum_test(datum_protocol_share_response(sizeof(rejected), rejected));
	datum_test(datum_accepted_share_count == 1);
	datum_test(datum_accepted_share_diff == (1ULL << 40));
	datum_test(datum_rejected_share_count == 1);
	datum_test(datum_rejected_share_diff == (1ULL << 40));
	accepted[7] = 63;
	datum_test(datum_protocol_share_response(sizeof(accepted), accepted));
	datum_test(datum_accepted_share_diff == (1ULL << 63) + (1ULL << 40));
	accepted[7] = 64;
	datum_test(datum_protocol_share_response(sizeof(accepted), accepted));
	datum_test(datum_accepted_share_diff == UINT64_MAX);
	rejected[7] = 64;
	datum_test(datum_protocol_share_response(sizeof(rejected), rejected));
	datum_test(datum_rejected_share_diff == UINT64_MAX);
	
	datum_accepted_share_count = saved_accepted_count;
	datum_accepted_share_diff = saved_accepted_diff;
	datum_rejected_share_count = saved_rejected_count;
	datum_rejected_share_diff = saved_rejected_diff;
}

static void datum_pow_recycled_protocol_job_test(void) {
	T_DATUM_STRATUM_JOB * const jobs = calloc(MAX_DATUM_PROTOCOL_JOBS + 1, sizeof(*jobs));
	T_DATUM_TEMPLATE_DATA * const templates = calloc(MAX_DATUM_PROTOCOL_JOBS + 1, sizeof(*templates));
	unsigned char msg[2048];
	T_DATUM_PROTOCOL_POW pow = {0};
	const bool saved_pass_full_users = datum_config.datum_pool_pass_full_users;
	const bool saved_pass_workers = datum_config.datum_pool_pass_workers;
	char saved_pool_address[sizeof(datum_config.mining_pool_address)];
	
	if (!jobs || !templates) {
		datum_test(jobs && templates);
		free(templates);
		free(jobs);
		return;
	}
	memcpy(saved_pool_address, datum_config.mining_pool_address, sizeof(saved_pool_address));
	datum_config.datum_pool_pass_full_users = false;
	datum_config.datum_pool_pass_workers = false;
	strcpy(datum_config.mining_pool_address, "pool");
	memset(datum_jobs, 0, sizeof(datum_jobs));
	datum_protocol_next_job_idx = 0;
	
	for(size_t i=0;i<MAX_DATUM_PROTOCOL_JOBS + 1;i++) {
		T_DATUM_STRATUM_JOB * const job = &jobs[i];
		job->block_template = &templates[i];
		job->height = 100 + i;
		job->coinbase_value = 5000000000ULL + i;
		job->target_pot_index = 4;
		job->datum_coinbaser_id = (unsigned char)i;
		job->prevhash_bin[0] = (unsigned char)(0xa0 + i);
		job->nbits_bin[0] = (unsigned char)(0xb0 + i);
		job->coinbase[2].coinb1_len = 1;
		job->coinbase[2].coinb2_len = 1;
		job->coinbase[2].coinb1_bin[0] = (unsigned char)(0xc0 + i);
		job->coinbase[2].coinb2_bin[0] = (unsigned char)(0xd0 + i);
		job->subsidy_only_coinbase.coinb1_len = 1;
		job->subsidy_only_coinbase.coinb2_len = 1;
		job->subsidy_only_coinbase.coinb1_bin[0] = (unsigned char)(0xe0 + i);
		job->subsidy_only_coinbase.coinb2_bin[0] = (unsigned char)(0xf0 + i);
		snprintf(job->job_id, sizeof(job->job_id), "job-%02zu", i);
	}
	
	pow.datum_job_id = datum_protocol_setup_new_job_idx(&jobs[0]);
	pow.sjob = &jobs[0];
	memcpy(pow.stratum_job_id, jobs[0].job_id, sizeof(pow.stratum_job_id));
	pow.coinbase_id = 2;
	pow.blake2b_use_time_offset = true;
	pow.ntime = UINT64_C(0x1817161514131211);
	pow.nonce = UINT64_C(0x0807060504030201);
	pow.time_on_wire = UINT32_C(0x6553412f);
	pow.version = UINT32_C(0x20000000);
	pow.target_byte_index = jobs[0].target_pot_index;
	pow.target_byte = 1;
	
	// A pool without ABW omits section 0x05 and uses the null XOR key.
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
	datum_test(msg[39] == 0x03 && msg[40] == DATUM_POW_BLAKE2B);
	datum_test(msg[57] == 0x04 && upk_u32le(msg, 58) == pow.time_on_wire);
	datum_test(msg[62] == 0x01 && msg[63] == 0xa0);
	datum_test(msg[131] == 0x02 && msg[137] == 0xc0 && msg[138] == 0xd0);
	memset(datum_jobs, 0, sizeof(datum_jobs));
	datum_protocol_next_job_idx = 0;
	pow.datum_job_id = datum_protocol_setup_new_job_idx(&jobs[0]);
	pow.abw_assignment_id = 1;
	
	// First use registers job 0 and its coinbase in remote slot 0.
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 142);
	datum_test((msg[3] & 0x08) != 0);
	datum_test(upk_u32le(msg, 13) == pow.version);
	datum_test((msg[35] & DATUM_POW_RESERVED_BLAKE2B_USE_TIME_OFFSET) != 0);
	datum_test(msg[39] == 0x03 && msg[40] == DATUM_POW_BLAKE2B);
	datum_test(upk_u64le(msg, 41) == pow.ntime);
	datum_test(upk_u64le(msg, 49) == pow.nonce);
	datum_test(msg[57] == 0x04 && upk_u32le(msg, 58) == pow.time_on_wire);
	datum_test(msg[62] == 0x05 && msg[63] == 0);
	datum_test(msg[64] == 0x01 && msg[65] == 0xa0);
	datum_test(msg[133] == 0x02 && msg[139] == 0xc0 && msg[140] == 0xd0);
	datum_test(datum_jobs[0].server_sjob == &jobs[0]);
	datum_test(!memcmp(datum_jobs[0].server_job_id, jobs[0].job_id,
		sizeof(datum_jobs[0].server_job_id)));
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) > 0);
	datum_test((msg[35] & DATUM_POW_RESERVED_BLAKE2B_USE_TIME_OFFSET) != 0);
	pow.blake2b_use_time_offset = false;
	
	// Malformed local state must not index beyond the six generated variants.
	pow.coinbase_id = MAX_COINBASE_TYPES;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 0);
	pow.coinbase_id = 2;
	pow.subsidy_only = true;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 0);
	pow.coinbase_id = DATUM_COINBASE_ID_EMPTY;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 73);
	datum_test((msg[3] & 0x02) != 0);
	datum_test(msg[64] == 0x02 && msg[65] == DATUM_COINBASE_ID_EMPTY);
	datum_test(msg[70] == 0xe0 && msg[71] == 0xf0);
	datum_test(datum_jobs[0].server_has_coinbase_empty);
	pow.subsidy_only = false;
	pow.coinbase_id = 2;
	
	// snprintf returns the untruncated length. Ensure a long address+worker is
	// capped to the actual bytes in the protocol username field.
	datum_config.datum_pool_pass_workers = true;
	memset(datum_config.mining_pool_address, 'a', sizeof(datum_config.mining_pool_address) - 1);
	datum_config.mining_pool_address[sizeof(datum_config.mining_pool_address) - 1] = 0;
	memset(pow.username, 'b', sizeof(pow.username) - 1);
	pow.username[sizeof(pow.username) - 1] = 0;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 445);
	datum_test(msg[414] == 0 && msg[444] == 0xFE);
	datum_config.datum_pool_pass_workers = false;
	strcpy(datum_config.mining_pool_address, "pool");
	pow.username[0] = 0;
	
	// Cycle the eight protocol IDs. Assigning job 8 reuses slot 0 and wipes
	// the remote cache so the next share must re-upload merkle and coinbase.
	for(size_t i=1;i<MAX_DATUM_PROTOCOL_JOBS + 1;i++) {
		jobs[i].datum_job_idx = datum_protocol_setup_new_job_idx(&jobs[i]);
	}
	datum_test(jobs[MAX_DATUM_PROTOCOL_JOBS].datum_job_idx == 0);
	datum_test(datum_jobs[0].sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);
	datum_test(datum_jobs[0].server_sjob == NULL);
	
	pow.sjob = &jobs[MAX_DATUM_PROTOCOL_JOBS];
	memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
	pow.target_byte_index = pow.sjob->target_pot_index;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 142);
	datum_test(msg[64] == 0x01 && msg[65] == 0xa8);
	datum_test(msg[133] == 0x02 && msg[139] == 0xc8 && msg[140] == 0xd8);
	datum_test(datum_jobs[0].server_sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);
	
	// A delayed share for the old job must switch the remote cache back to its
	// exact context; a following new-job share must switch it forward again.
	pow.sjob = &jobs[0];
	memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 142);
	datum_test(msg[65] == 0xa0 && msg[139] == 0xc0 && msg[140] == 0xd0);
	datum_test(datum_jobs[0].server_sjob == &jobs[0]);
	pow.sjob = &jobs[MAX_DATUM_PROTOCOL_JOBS];
	memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 142);
	datum_test(msg[65] == 0xa8 && msg[139] == 0xc8 && msg[140] == 0xd8);
	datum_test(datum_jobs[0].server_sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);
	
	// Reusing the same local object for a new job must still replace Apex's
	// cached context. Pointer identity alone cannot distinguish ring reuse.
	snprintf(jobs[MAX_DATUM_PROTOCOL_JOBS].job_id,
		sizeof(jobs[MAX_DATUM_PROTOCOL_JOBS].job_id), "same-pointer-reuse");
	memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 142);
	datum_test(!memcmp(datum_jobs[0].server_job_id, pow.stratum_job_id,
		sizeof(datum_jobs[0].server_job_id)));
	
	memset(datum_jobs, 0, sizeof(datum_jobs));
	datum_protocol_next_job_idx = 0;
	memcpy(datum_config.mining_pool_address, saved_pool_address, sizeof(saved_pool_address));
	datum_config.datum_pool_pass_full_users = saved_pass_full_users;
	datum_config.datum_pool_pass_workers = saved_pass_workers;
	free(templates);
	free(jobs);
}

static void datum_protocol_stxlist_byid_tests(void) {
	// A 0x50 0x11 request names transaction indices with nothing against
	// repeats, and the reply is built in the fixed temp_data buffer. The
	// handler has to refuse a list the reply cannot hold instead of writing
	// past the end of the buffer.
	T_DATUM_STRATUM_JOB * const job = calloc(1, sizeof(*job));
	T_DATUM_TEMPLATE_DATA * const block_template = calloc(1, sizeof(*block_template));
	const uint32_t txn_size = 100000;
	const uint32_t txn_count = 64;
	T_DATUM_TEMPLATE_TXN * const txns = calloc(txn_count, sizeof(*txns));
	unsigned char * const txn_data = malloc(txn_size);
	unsigned char * const tail = temp_data + DATUM_PROTOCOL_TEMP_DATA_SIZE - 64;
	unsigned char request[3 + 2 * 64];
	unsigned char canary[64];
	const int saved_out = server_out_buf;
	const uint32_t saved_header_key = sending_header_key;
	unsigned char saved_nonce[sizeof(session_nonce_sender)];
	unsigned char job_index;
	size_t k;
	
	memcpy(saved_nonce, session_nonce_sender, sizeof(saved_nonce));
	datum_test(job && block_template && txns && txn_data);
	if (!job || !block_template || !txns || !txn_data) goto cleanup;
	
	memset(txn_data, 0x5a, txn_size);
	for (k = 0; k < txn_count; ++k) {
		txns[k].size = txn_size;
		txns[k].txn_data_binary = txn_data;
	}
	block_template->txn_count = txn_count;
	block_template->txns = txns;
	job->block_template = block_template;
	snprintf(job->job_id, sizeof(job->job_id), "stxlist");
	memset(datum_jobs, 0, sizeof(datum_jobs));
	datum_protocol_next_job_idx = 0;
	job_index = datum_protocol_setup_new_job_idx(job);
	datum_jobs[job_index].server_sjob = job;
	memcpy(datum_jobs[job_index].server_job_id, job->job_id,
		sizeof(datum_jobs[job_index].server_job_id));
	server_out_buf = 0;
	memset(canary, 0xc7, sizeof(canary));
	memcpy(tail, canary, sizeof(canary));
	
	// Two distinct transactions fit and are answered.
	request[0] = job_index;
	pk_u16le(request, 1, 2);
	pk_u16le(request, 3, 0);
	pk_u16le(request, 5, 1);
	datum_test(datum_protocol_job_validation_stxlist_byid(7, request) == 1);
	datum_test(temp_data[0] == 0x50 && temp_data[1] == 0x91);
	datum_test(temp_data[2] == job_index && temp_data[3] == 0x01);
	datum_test(upk_u16le(temp_data, 4) == 2);
	datum_test(!memcmp(tail, canary, sizeof(canary)));
	server_out_buf = 0;
	
	// The largest transaction 64 times over would need 6.4 MB. The count
	// alone passes the txn_count gate; the reply must be refused.
	pk_u16le(request, 1, 64);
	for (k = 0; k < 64; ++k) pk_u16le(request, 3 + 2 * k, 0);
	datum_test(datum_protocol_job_validation_stxlist_byid(3 + 2 * 64, request) == 1);
	datum_test(temp_data[2] == job_index && temp_data[3] == 0xF4);
	datum_test(!memcmp(tail, canary, sizeof(canary)));
	server_out_buf = 0;
	
	// A list cut short of its count is refused before it is read.
	pk_u16le(request, 1, 4);
	temp_data[3] = 0;
	datum_test(datum_protocol_job_validation_stxlist_byid(3 + 2 * 3, request) == 1);
	datum_test(temp_data[2] == job_index && temp_data[3] == 0xF4);
	datum_test(datum_protocol_job_validation_stxlist_byid(2, request) == 0);
	
	// The bound leaves room for the terminator and the padding.
	datum_test(datum_protocol_stxlist_reply_fits(0, txn_size));
	datum_test(datum_protocol_stxlist_reply_fits(DATUM_STXLIST_REPLY_MAX - 3 - txn_size, txn_size));
	datum_test(!datum_protocol_stxlist_reply_fits(DATUM_STXLIST_REPLY_MAX - 2 - txn_size, txn_size));
	
cleanup:
	datum_protocol_bulk_reset();
	memset(datum_jobs, 0, sizeof(datum_jobs));
	datum_protocol_next_job_idx = 0;
	server_out_buf = saved_out;
	sending_header_key = saved_header_key;
	memcpy(session_nonce_sender, saved_nonce, sizeof(saved_nonce));
	free(txn_data);
	free(txns);
	free(block_template);
	free(job);
}

void datum_protocol_tests(void) {
	datum_protocol_config_v3_tests();
	datum_protocol_migration_tests();
	datum_protocol_bulk_tests();
	datum_protocol_resume_tests();
	datum_protocol_abw_cache_tests();
	datum_pow_response_large_difficulty_test();
	datum_pow_recycled_protocol_job_test();
	datum_protocol_stxlist_byid_tests();
}
