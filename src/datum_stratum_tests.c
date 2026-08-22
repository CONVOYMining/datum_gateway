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
 * Copyright (c) 2025 Bitcoin Ocean, LLC & Luke Dashjr
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
#include <stdlib.h>
#include <string.h>

#include "datum_jsonrpc.h"
#include "datum_pow.h"
#include "datum_protocol.h"
#include "datum_queue.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_utils.h"

void stratum_calculate_merkle_branches(T_DATUM_STRATUM_JOB *s);
int client_mining_submit(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);
int datum_protocol_share_response(int len, unsigned char *data);
int datum_protocol_pow(void *arg);
int datum_stratum_coinbase_fit_to_template(int max_sz, int fixed_bytes, T_DATUM_STRATUM_JOB *s);
extern DATUM_QUEUE pow_queue;
extern unsigned char datum_protocol_next_job_idx;
extern T_DATUM_PROTOCOL_JOB datum_jobs[MAX_DATUM_PROTOCOL_JOBS];

static void datum_gbt_header_fields_tests(void) {
       T_DATUM_TEMPLATE_DATA tdata;
       json_error_t error;
       json_t *gbt;
       const bool saved_allow_time_rolling = datum_config.mining_allow_hasher_time_rolling;
       datum_config.mining_allow_hasher_time_rolling = false;

       memset(&tdata, 0xff, sizeof(tdata));
       gbt = json_object();
       datum_test(gbt != NULL);
       datum_test(!datum_gbt_parse_header_fields(gbt, &tdata));
       datum_test(tdata.header_version == 0);
       datum_test(tdata.header_transaction_count == 0);
       datum_test(tdata.header_flags == 0);
       datum_test(tdata.header_time_offset == 0);
       datum_test(tdata.xor_key_mask_clear_bits == 0);
       json_decref(gbt);

       gbt = json_pack("{s:i}", "header_version", 0);
       datum_test(gbt != NULL);
       datum_test(!datum_gbt_parse_header_fields(gbt, &tdata));
       json_decref(gbt);

       gbt = json_loads(
               "{\"powalgorithm\":\"blake2b\",\"transaction_count\":\"ignored\","
               "\"h1_flags\":999,\"time_offset\":-1,"
               "\"xor_key_mask_clear_bits\":999,\"xor_key\":\"not-a-secret\","
               "\"merge_mining_rhs\":false}", 0, &error);
       datum_test(gbt != NULL);
       memset(&tdata, 0, sizeof(tdata));
       datum_test(datum_gbt_parse_header_fields(gbt, &tdata));
       datum_test(tdata.header_version == 2);
       datum_test(tdata.header_transaction_count == 0);
       datum_test(tdata.header_flags == 0);
       datum_test(tdata.header_time_offset == 0);
       datum_test(tdata.xor_key_mask_clear_bits == 0);
       for(size_t i=0;i<sizeof(tdata.xor_key);i++) datum_test(tdata.xor_key[i] == 0);
       for(size_t i=0;i<sizeof(tdata.merge_mining_rhs);i++) {
               datum_test(tdata.merge_mining_rhs[i] == 0);
       }

       datum_config.mining_allow_hasher_time_rolling = true;
       datum_test(datum_gbt_parse_header_fields(gbt, &tdata));
       datum_test(tdata.header_flags == DATUM_BLAKE2B_USE_TIME_OFFSET);
       datum_config.mining_allow_hasher_time_rolling = false;

       json_object_set_new(gbt, "powalgorithm", json_string("unsupported"));
       datum_test(!datum_gbt_parse_header_fields(gbt, &tdata));
       json_object_set_new(gbt, "powalgorithm", json_integer(2));
       datum_test(!datum_gbt_parse_header_fields(gbt, &tdata));
       json_decref(gbt);

       gbt = json_loads("{\"powalgorithm\":\"sha256d\"}", 0, &error);
       datum_test(gbt != NULL);
       memset(&tdata, 0xff, sizeof(tdata));
       datum_test(datum_gbt_parse_header_fields(gbt, &tdata));
       datum_test(tdata.header_version == 0);
       json_decref(gbt);

       gbt = json_loads("{\"powalgorithm\":\"sha256d\",\"header_version\":2}", 0, &error);
       datum_test(gbt != NULL);
       datum_test(!datum_gbt_parse_header_fields(gbt, &tdata));
       json_decref(gbt);

       gbt = json_loads("{\"header_version\":2}", 0, &error);
       datum_test(gbt != NULL);
       datum_test(datum_gbt_parse_header_fields(gbt, &tdata));
       datum_test(tdata.header_version == 2);
       json_decref(gbt);
       datum_config.mining_allow_hasher_time_rolling = saved_allow_time_rolling;
}

static void datum_gbt_rules_blake2b_tests(void) {
       json_error_t error;
       json_t *gbt;
       char saved_pow[sizeof(datum_config.mining_pow_algorithm)];

       memcpy(saved_pow, datum_config.mining_pow_algorithm, sizeof(saved_pow));

       strcpy(datum_config.mining_pow_algorithm, "auto");
       datum_test(datum_gbt_advertise_blake2b());
       strcpy(datum_config.mining_pow_algorithm, "blake2b");
       datum_test(datum_gbt_advertise_blake2b());
       strcpy(datum_config.mining_pow_algorithm, "sha256d");
       datum_test(!datum_gbt_advertise_blake2b());

       gbt = json_loads("{\"rules\":[\"segwit\"]}", 0, &error);
       datum_test(gbt != NULL);
       datum_test(!datum_gbt_rules_want_blake2b(gbt));
       json_decref(gbt);

       gbt = json_loads("{\"rules\":[\"segwit\",\"!blake2b\"]}", 0, &error);
       datum_test(gbt != NULL);
       datum_test(datum_gbt_rules_want_blake2b(gbt));
       json_decref(gbt);

       gbt = json_loads("{\"rules\":[\"blake2b\",\"segwit\"]}", 0, &error);
       datum_test(gbt != NULL);
       datum_test(datum_gbt_rules_want_blake2b(gbt));
       json_decref(gbt);

       datum_test(!datum_gbt_rules_want_blake2b(NULL));
       gbt = json_object();
       datum_test(gbt != NULL);
       datum_test(!datum_gbt_rules_want_blake2b(gbt));
       json_decref(gbt);

       memcpy(datum_config.mining_pow_algorithm, saved_pow, sizeof(saved_pow));
}

static void datum_blake2b_coinbase_limit_tests(void) {
       T_DATUM_TEMPLATE_DATA tdata;
       T_DATUM_STRATUM_JOB job;

       memset(&tdata, 0, sizeof(tdata));
       memset(&job, 0, sizeof(job));
       job.block_template = &tdata;
       tdata.sizelimit = 85 + 36 + 950;
       tdata.weightlimit = 4000000;

       /* SHA256d (80-byte header) keeps the original leftover size. */
       datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 950);

       /* Header v2 is 84 bytes larger; shrink the coinbase leftover by that. */
       tdata.header_version = 2;
       datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 866);
}

static void datum_block_coinbase_witness_tests(void) {
       static const unsigned char stripped[] = {
               0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
       };
       static const unsigned char witnessed[] = {
               0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
       };
       static const char zero_witness[] =
               "01200000000000000000000000000000000000000000000000000000000000000000";
       char output[256] = {0};
       T_DATUM_TEMPLATE_DATA tdata = {0};
       T_DATUM_STRATUM_JOB job = {.block_template = &tdata};
       size_t size;

       datum_test(!datum_stratum_block_needs_witness(&job, false));
       tdata.default_witness_commitment[0] = '1';
       datum_test(datum_stratum_block_needs_witness(&job, false));
       datum_test(!datum_stratum_block_needs_witness(&job, true));
       datum_test(!datum_stratum_block_needs_witness(NULL, false));

       size = datum_stratum_coinbase_for_block_hex(
               output, sizeof(output), stripped, sizeof(stripped), true);
       output[size] = 0;
       datum_test(size == (sizeof(stripped) + 36) * 2);
       datum_test(!strncmp(output, "0100000000010102", 16));
       datum_test(!strncmp(output + 16, zero_witness, sizeof(zero_witness) - 1));
       datum_test(!strcmp(output + 16 + sizeof(zero_witness) - 1, "00000000"));

       memset(output, 0, sizeof(output));
       size = datum_stratum_coinbase_for_block_hex(
               output, sizeof(output), witnessed, sizeof(witnessed), true);
       datum_test(size == sizeof(witnessed) * 2);
       datum_test(!strncmp(output, "010000000001010200000000", size));

       memset(output, 0, sizeof(output));
       size = datum_stratum_coinbase_for_block_hex(
               output, sizeof(output), stripped, sizeof(stripped), false);
       datum_test(size == sizeof(stripped) * 2);
       datum_test(!strncmp(output, "01000000010200000000", size));
       datum_test(!datum_stratum_coinbase_for_block_hex(
               output, (sizeof(stripped) + 36) * 2 - 1, stripped, sizeof(stripped), true));
       datum_test(!datum_stratum_coinbase_for_block_hex(
               output, sizeof(output), stripped, 7, true));
}

static void datum_pow_blake2b_vector_tests(void) {
       /* H1+H2 match Knots CBlockHeader::GetHash with wire version bit 0x80000000 in H1. */
       static const char expected_commitment_hex[] =
               "be3009118e9fbe8be787c9fef5ee1a34c95b92efe7c6f1d430c488e094ce94a8";
       static const char expected_root_hex[] =
               "2ae3e2ac5e7b16faeda5b13386d9b3fb0e5ddfa803deee88eb9a1f6ce65c9110";
       static const char expected_work_hex[] =
               "0000000000008a7f7054908ed879cc78d133dc6604fb0fd017552289799cabd6"
               "01020304050607080403020115161718"
               "2ae3e2ac5e7b16faeda5b13386d9b3fb0e5ddfa803deee88eb9a1f6ce65c9110";
       static const char expected_hash_le_hex[] =
               "15ed05ccf950c40f149ea623b77f7f3f58afb9ab3ab723d5ca5870338c42d935";
       static const char expected_header_hex[] =
               "000000a0c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2f415365ffff7f20"
               "01020304050607081516171800000000a0a1a2a3a4a5a6a7a8a9aaab040302010300040d"
               "101112131415161718191a1b1c1d1e1f39300000"
               "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
       unsigned char merkle[32], xor_key[16], rhs[32], extranonce[12], prevhash[32];
       unsigned char nonce[8], ntime[8], commitment[32], root[32], work[80], hash_le[32];
       unsigned char share_target[32];
       unsigned char sia_coinb1[39], arbitrary_tx[51], leaf_preimage[52] = {0};
       unsigned char header[DATUM_BLAKE2B_BLOCK_HEADER_SIZE], expected[DATUM_BLAKE2B_BLOCK_HEADER_SIZE];
       uint32_t time_on_wire;

       datum_test(datum_blake2b_time_on_wire(&time_on_wire, 2000000000, 600,
               DATUM_BLAKE2B_USE_TIME_OFFSET));
       datum_test(time_on_wire == 1999999400);
       // Consensus wraps rather than rejecting when the offset exceeds nTime.
       datum_test(datum_blake2b_time_on_wire(&time_on_wire, 599, 600,
               DATUM_BLAKE2B_USE_TIME_OFFSET));
       datum_test(time_on_wire == 4294967295u);
       datum_test(datum_blake2b_time_on_wire(&time_on_wire, 100, 1000,
               DATUM_BLAKE2B_USE_TIME_OFFSET));
       datum_test(time_on_wire == 4294966396u);
       datum_test(!datum_blake2b_time_on_wire(&time_on_wire,
               UINT64_C(0x100000000), 0, 0));
       datum_test(datum_blake2b_time_on_wire(&time_on_wire, 599, 600, 0));
       datum_test(time_on_wire == 599);
       datum_test(datum_blake2b_share_target(share_target, 4));
       for(size_t i=0;i<27;i++) datum_test(share_target[i] == 0xff);
       datum_test(share_target[27] == 0x0f);
       for(size_t i=28;i<32;i++) datum_test(share_target[i] == 0);
       datum_test(!datum_blake2b_share_target(share_target, 224));
       datum_test(datum_blake2b_sia_difficulty(1) == 0.9999847412109375L);
       datum_test(datum_blake2b_sia_difficulty(16) == 15.999755859375L);
       datum_test(datum_blake2b_accounting_difficulty(65535.0L) == 65536.0L);

       for(size_t i=0;i<32;i++) {
               merkle[i] = i;
               rhs[i] = 0x80 + i;
               prevhash[i] = 0xc0 + i;
       }
       for(size_t i=0;i<16;i++) xor_key[i] = 0x10 + i;
       for(size_t i=0;i<12;i++) extranonce[i] = 0xa0 + i;
       for(size_t i=0;i<8;i++) nonce[i] = 1 + i;
       pk_u32le(ntime, 0, UINT32_C(0x01020304));
       pk_u32le(ntime, 4, UINT32_C(0x18171615));
       datum_test(datum_blake2b_header_commitment(commitment, 0x20000000, prevhash,
               12345, merkle, 0x6553412f, 0x207fffff, 3, DATUM_BLAKE2B_USE_TIME_OFFSET, 13,
               xor_key, rhs));
       datum_test(datum_pow_decode_hex_exact(expected_commitment_hex, 32, expected));
       datum_test(!memcmp(commitment, expected, 32));
       datum_test(datum_blake2b_work_root(root, commitment, extranonce));
       datum_test(datum_pow_decode_hex_exact(expected_root_hex, 32, expected));
       datum_test(!memcmp(root, expected, 32));
       datum_blake2b_sia_coinb1(sia_coinb1, commitment);
       memcpy(arbitrary_tx, sia_coinb1, sizeof(sia_coinb1));
       memcpy(arbitrary_tx + sizeof(sia_coinb1), extranonce, sizeof(extranonce));
       memcpy(leaf_preimage + 1, arbitrary_tx, sizeof(arbitrary_tx));
       datum_test(datum_blake2b_256(expected, leaf_preimage, sizeof(leaf_preimage)));
       datum_test(!memcmp(root, expected, 32));
       datum_blake2b_build_work_header(work, prevhash, nonce, ntime, root);
       datum_test(datum_pow_decode_hex_exact(expected_work_hex, sizeof(work), expected));
       datum_test(!memcmp(work, expected, sizeof(work)));
       datum_blake2b_sia_prevhash(expected, prevhash);
       datum_test(!memcmp(expected, work, 32));
       datum_test(datum_blake2b_pow_hash_le(hash_le, work, xor_key, 13));
       datum_test(datum_pow_decode_hex_exact(expected_hash_le_hex, 32, expected));
       datum_test(!memcmp(hash_le, expected, 32));
       datum_blake2b_serialize_block_header(header, 0x20000000, prevhash, merkle,
               0x6553412f, 0x207fffff, nonce, ntime, extranonce, 3,
               DATUM_BLAKE2B_USE_TIME_OFFSET, 13, xor_key, 12345, rhs);
       datum_test(datum_pow_decode_hex_exact(expected_header_hex, sizeof(header), expected));
       datum_test(!memcmp(header, expected, sizeof(header)));
       datum_test(!datum_pow_decode_hex_exact("xyz", 1, nonce));

       /* Canonical profile-0 vector published with Knots' header-v2 implementation. */
       {
               static const char knots_prevhash_hex[] =
                       "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
               static const char knots_merkle_hex[] =
                       "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0";
               static const char knots_rhs_hex[] =
                       "8967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab";
               static const char knots_commitment_hex[] =
                       "39a5eb49a0907424d78db90ff6701f701d5044486c0434059d4320452ffe4f0b";
               static const char knots_root_hex[] =
                       "8e55344843862b11ce8d74d726940b00b3235d2cf57139fa9c6c20ce0c77e32a";
               static const char knots_work_hex[] =
                       "000000000000943aff74219e1f45899abfdf536373c0f2fc92e6fe58335cd0ad"
                       "0df0ad0b4433221158020000efcdab89"
                       "8e55344843862b11ce8d74d726940b00b3235d2cf57139fa9c6c20ce0c77e32a";
               static const char knots_hash_le_hex[] =
                       "0c614ddef4b5d55119982e7515d592dc02d61a4ce66d833b02ecaaee643de235";
               unsigned char knots_prevhash[32], knots_merkle[32], knots_rhs[32];
               unsigned char knots_nonce[8], knots_ntime[8];

               datum_test(datum_pow_decode_hex_exact(knots_prevhash_hex, 32, knots_prevhash));
               datum_test(datum_pow_decode_hex_exact(knots_merkle_hex, 32, knots_merkle));
               datum_test(datum_pow_decode_hex_exact(knots_rhs_hex, 32, knots_rhs));
               memset(xor_key, 0, sizeof(xor_key));
               pk_u32le(knots_nonce, 0, UINT32_C(0x0badf00d));
               pk_u32le(knots_nonce, 4, UINT32_C(0x11223344));
               pk_u32le(knots_ntime, 0, UINT32_C(600));
               pk_u32le(knots_ntime, 4, UINT32_C(0x89abcdef));

               datum_test(datum_blake2b_header_commitment(commitment, 0x20000000,
                       knots_prevhash, 840000, knots_merkle, UINT32_C(2000000000) - 600,
                       0x1d00ffff, 3, 0x5c, 0, xor_key, knots_rhs));
               datum_test(datum_pow_decode_hex_exact(knots_commitment_hex, 32, expected));
               datum_test(!memcmp(commitment, expected, 32));

               datum_test(datum_pow_decode_hex_exact(knots_root_hex, 32, root));
               datum_blake2b_build_work_header(work, knots_prevhash, knots_nonce,
                       knots_ntime, root);
               datum_test(datum_pow_decode_hex_exact(knots_work_hex, sizeof(work), expected));
               datum_test(!memcmp(work, expected, sizeof(work)));
               datum_test(datum_blake2b_pow_hash_le(hash_le, work, xor_key, 0));
               datum_test(datum_pow_decode_hex_exact(knots_hash_le_hex, 32, expected));
               datum_test(!memcmp(hash_le, expected, 32));
       }
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

static void datum_pow_sia_dupe_tests(void) {
       T_DATUM_STRATUM_DUPE_ITEM items[8] = {0};
       T_DATUM_STRATUM_DUPES * const dupes = calloc(1, sizeof(*dupes));
       T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
       unsigned char unaligned_extranonce[13] = {0};
       unsigned char * const extranonce = unaligned_extranonce + 1;
       const uint64_t nonce_low = 0x0000000012345678ULL;
       const uint64_t nonce_high = 0xabcdef0012345678ULL;

       for (size_t i = 0; i < 12; ++i) {
               extranonce[i] = (unsigned char)(i + 1);
       }
       datum_test(dupes != NULL);
       datum_test(thread_data != NULL);
       if (!dupes || !thread_data) {
               free(dupes);
               free(thread_data);
               return;
       }
       dupes->ptr = items;
       dupes->max_items = 8;
       thread_data->dupes = dupes;
       datum_test(!datum_stratum_check_for_dupe(thread_data, nonce_low, 1, 2, 0, extranonce));
       datum_test(!datum_stratum_check_for_dupe(thread_data, nonce_high, 1, 2, 0, extranonce));
       datum_test(datum_stratum_check_for_dupe(thread_data, nonce_low, 1, 2, 0, extranonce));
       datum_test(datum_stratum_check_for_dupe(thread_data, nonce_high, 1, 2, 0, extranonce));
       free(dupes);
       free(thread_data);
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
               datum_test(false);
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

       // First use registers job 0 and its coinbase in remote slot 0.
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
       datum_test((msg[3] & 0x08) != 0);
       datum_test(upk_u32le(msg, 13) == pow.version);
       datum_test((msg[35] & DATUM_POW_RESERVED_BLAKE2B_USE_TIME_OFFSET) != 0);
       datum_test(msg[39] == 0x03 && msg[40] == DATUM_POW_BLAKE2B);
       datum_test(upk_u64le(msg, 41) == pow.ntime);
       datum_test(upk_u64le(msg, 49) == pow.nonce);
       datum_test(msg[57] == 0x04 && upk_u32le(msg, 58) == pow.time_on_wire);
       datum_test(msg[62] == 0x01 && msg[63] == 0xa0);
       datum_test(msg[131] == 0x02 && msg[137] == 0xc0 && msg[138] == 0xd0);
       datum_test(datum_jobs[0].server_sjob == &jobs[0]);
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) > 0);
       datum_test((msg[35] & DATUM_POW_RESERVED_BLAKE2B_USE_TIME_OFFSET) != 0);
       pow.blake2b_use_time_offset = false;

       // Malformed local state must not index beyond the six generated variants.
       pow.coinbase_id = MAX_COINBASE_TYPES;
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 0);
       pow.coinbase_id = 2;
       pow.subsidy_only = true;
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 0);
       pow.subsidy_only = false;

       // snprintf returns the untruncated length. Ensure a long address+worker is
       // capped to the actual bytes in the protocol username field.
       datum_config.datum_pool_pass_workers = true;
       memset(datum_config.mining_pool_address, 'a', sizeof(datum_config.mining_pool_address) - 1);
       datum_config.mining_pool_address[sizeof(datum_config.mining_pool_address) - 1] = 0;
       memset(pow.username, 'b', sizeof(pow.username) - 1);
       pow.username[sizeof(pow.username) - 1] = 0;
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 443);
       datum_test(msg[414] == 0 && msg[442] == 0xFE);
       datum_config.datum_pool_pass_workers = false;
       strcpy(datum_config.mining_pool_address, "pool");
       pow.username[0] = 0;

       // Cycle the eight protocol IDs. Merely assigning job 8 must leave remote
       // slot 0 bound to job 0 until a share for the new job is actually sent.
       for(size_t i=1;i<MAX_DATUM_PROTOCOL_JOBS + 1;i++) {
               jobs[i].datum_job_idx = datum_protocol_setup_new_job_idx(&jobs[i]);
       }
       datum_test(jobs[MAX_DATUM_PROTOCOL_JOBS].datum_job_idx == 0);
       datum_test(datum_jobs[0].server_sjob == &jobs[0]);

       pow.sjob = &jobs[MAX_DATUM_PROTOCOL_JOBS];
       memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
       pow.target_byte_index = pow.sjob->target_pot_index;
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
       datum_test(msg[62] == 0x01 && msg[63] == 0xa8);
       datum_test(msg[131] == 0x02 && msg[137] == 0xc8 && msg[138] == 0xd8);
       datum_test(datum_jobs[0].server_sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);

       // A delayed share for the old job must switch the remote cache back to its
       // exact context; a following new-job share must switch it forward again.
       pow.sjob = &jobs[0];
       memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
       datum_test(msg[63] == 0xa0 && msg[137] == 0xc0 && msg[138] == 0xd0);
       datum_test(datum_jobs[0].server_sjob == &jobs[0]);
       pow.sjob = &jobs[MAX_DATUM_PROTOCOL_JOBS];
       memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
       datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
       datum_test(msg[63] == 0xa8 && msg[137] == 0xc8 && msg[138] == 0xd8);
       datum_test(datum_jobs[0].server_sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);

       memset(datum_jobs, 0, sizeof(datum_jobs));
       datum_protocol_next_job_idx = 0;
       memcpy(datum_config.mining_pool_address, saved_pool_address, sizeof(saved_pool_address));
       datum_config.datum_pool_pass_full_users = saved_pass_full_users;
       datum_config.datum_pool_pass_workers = saved_pass_workers;
       free(templates);
       free(jobs);
}

static void datum_stratum_string_request_id_tests(void) {
       T_DATUM_CLIENT_DATA client = {0};
       T_DATUM_MINER_DATA miner = {0};
       char authorize[] =
               "{\"id\":\"authorize-17\",\"method\":\"mining.authorize\","
               "\"params\":[\"hardware.worker\",\"password\"]}";
       char authorize_numeric[] =
               "{\"id\":18,\"method\":\"mining.authorize\","
               "\"params\":[\"hardware.worker\",\"password\"]}";
       char unknown[] =
               "{\"id\":\"unknown-19\",\"method\":\"mining.unknown\",\"params\":[]}";
       char oversized[512];

       client.app_client_data = &miner;
       datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize) == 0);
       datum_test(miner.authorized);
       datum_test(!strcmp(miner.last_auth_username, "hardware.worker"));
       datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n"));
       datum_test(!memcmp(client.w_buffer,
               "{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n", client.out_buf));
       datum_test(miner.request_id_json[0] == 0);
       client.out_buf = 0;
       datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize_numeric) == 0);
       datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":18,\"result\":true}\n"));
       datum_test(!memcmp(client.w_buffer,
               "{\"error\":null,\"id\":18,\"result\":true}\n", client.out_buf));
       client.out_buf = 0;
       datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, unknown) == 0);
       datum_test(client.out_buf == (int)strlen(
               "{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n"));
       datum_test(!memcmp(client.w_buffer,
               "{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n",
               client.out_buf));
       datum_test(miner.request_id_json[0] == 0);
       snprintf(oversized, sizeof(oversized),
               "{\"id\":\"%0130d\",\"method\":\"mining.authorize\",\"params\":[]}", 0);
       datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, oversized) == -4);
}


void datum_stratum_mod_username_tests() {
	const char * const s_umods = "{\"x\":{\"addrA\": 0.3}, \"abc\":{\"addrB\":0.3,\"addrC\":0.3},\":)\":{\"\":0.5}}";
	json_error_t err;
	json_t * const j_umods = JSON_LOADS(s_umods, &err);
	assert(j_umods);
	struct datum_username_mod *umods = NULL;
	int ret = datum_config_parse_username_mods(&umods, j_umods, false);
	assert(ret == 1);
	json_decref(j_umods);
	datum_config.stratum_username_mod = umods;
	
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s, *modname;
	const char *res, *a1, *a2;
	
	strcpy(pool_addr, "dummy");
	
	s = "def~G";
	modname = &s[4];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1) == s);
	
	s = "def~x";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 1) == pool_addr);
	
	s = "def~abc";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	if (0 == strcmp(res, "addrB")) {  // jansson doesn't order keys'
		a1 = "addrB";
		a2 = "addrC";
	} else {
		a1 = "addrC";
		a2 = "addrB";
	}
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3);
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3);
	datum_test(0 == strcmp(res, a2));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3);
	datum_test(0 == strcmp(res, a2));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~abc";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~:)";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	memset(buf, 0, 7);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x7fff, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x8000, modname, 2) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 2) == pool_addr);
	
	// Intentionally overflow buf with address: we lose the worker name, but get the full address via its umod buffer
	s = "def.ghi~x";
	modname = &s[8];
	memset(buf, 0x0e, 8);
	res = datum_stratum_mod_username(s, buf, 2, 0, modname, 1);
	datum_test(res != buf);
	datum_test(res != pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	res = datum_stratum_mod_username(s, buf, 2, 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, 2, 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0xffff, modname, 1) == pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(buf[6] == 0x0e);
	res = datum_stratum_mod_username(s, buf, 6, 0, modname, 1);
	datum_test(res == buf);
	datum_test(res != pool_addr);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 1) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "addrA."));
	memset(buf, 0x0e, 10);
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 1) == buf);
	datum_test(buf[9] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.g"));
	memset(buf, 0x0e, 11);
	datum_test(datum_stratum_mod_username(s, buf, 9, 0, modname, 1) == buf);
	datum_test(buf[10] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.gh"));
	memset(buf, 0x0e, 12);
	datum_test(datum_stratum_mod_username(s, buf, 10, 0, modname, 1) == buf);
	datum_test(buf[11] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.ghi"));
	s = "def.ghi~:)";
	modname = &s[8];
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0, modname, 2) == buf);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "d"));
	datum_test(datum_stratum_mod_username(s, buf, 6, 0, modname, 2) == buf);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "def.g"));
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 2) == buf);
	datum_test(buf[7] == 0x0e);
	datum_test(0 == strcmp(res, "def.gh"));
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 2) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "def.ghi"));
}

void datum_stratum_tests(void) {
	datum_stratum_mod_username_tests();
	datum_stratum_string_request_id_tests();
	datum_gbt_header_fields_tests();
	datum_gbt_rules_blake2b_tests();
    datum_blake2b_coinbase_limit_tests();
    datum_block_coinbase_witness_tests();
    datum_pow_blake2b_vector_tests();
    datum_pow_response_large_difficulty_test();
    datum_pow_sia_dupe_tests();
    datum_pow_recycled_protocol_job_test();
}
