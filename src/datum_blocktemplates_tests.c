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

#include <jansson.h>
#include <string.h>

#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_pow.h"
#include "datum_utils.h"

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
void datum_blocktemplates_tests(void) {
	datum_gbt_header_fields_tests();
	datum_gbt_rules_blake2b_tests();
}
