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

#include "datum_blocktemplates.h"
#include "datum_utils.h"

static void datum_gbt_rules_blake2b_tests(void) {
	json_error_t error;
	json_t *gbt;
	
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
	
	gbt = json_loads("{\"rules\":[\"!blake2b-extra\",\"xblake2b\"]}", 0, &error);
	datum_test(gbt != NULL);
	datum_test(!datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
	
	datum_test(!datum_gbt_rules_want_blake2b(NULL));
	gbt = json_object();
	datum_test(gbt != NULL);
	datum_test(!datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
}

static void datum_blocktemplates_abw_mode_tests(void) {
	T_DATUM_TEMPLATE_DATA block_template = {0};
	
	// Local work uses the null XOR key and needs no pool assignment.
	datum_test(datum_blocktemplates_abw_ready(
		&block_template, false, true));
	datum_test(!block_template.abw_enabled);
	datum_test(block_template.abw_assignment_id == 0);
	
	// A pool with ABW disabled also uses the null XOR key.
	datum_test(datum_blocktemplates_abw_ready(
		&block_template, true, false));
	datum_test(!block_template.abw_enabled);
	datum_test(block_template.abw_assignment_id == 0);
	
	// An ABW pool waits for its active assignment.
	datum_test(!datum_blocktemplates_abw_ready(
		&block_template, true, true));
}

// The ABW candidate cache shares one copy of a template's transactions between
// templates with the same content hash, so the parser must set it, and it must
// separate templates that differ only in which transactions they carry or their
// order: same count, same sizes, different wtxids.
static void datum_template_content_hash_tests(void) {
	static const char gbt_fmt[] =
		"{\"rules\":[\"!segwit\",\"!blake2b\"],"
		"\"height\":900000,\"coinbasevalue\":312500000,\"mintime\":1,\"sigoplimit\":80000,"
		"\"curtime\":2000000000,\"sizelimit\":4000000,\"weightlimit\":4000000,"
		"\"version\":536870912,\"bits\":\"1d00ffff\","
		"\"previousblockhash\":\"%064d\",\"target\":\"%064d\","
		"\"default_witness_commitment\":\"6a24aa21a9ed%052d\","
		"\"transactions\":[%s]}";
	static const char tx[] =
		"{\"txid\":\"%064d\",\"hash\":\"%064d\",\"fee\":1000,\"sigops\":1,"
		"\"weight\":400,\"data\":\"0100000000\"}";
	static const unsigned char zero[32] = {0};
	const int sets[4][2] = { {1, 2}, {1, 2}, {1, 3}, {2, 1} };
	unsigned char hashes[4][32];
	char t1[512], t2[512], txs[1100], gbt[2048];
	json_error_t error;

	datum_test(datum_template_init() > 0);
	for (int k = 0; k < 4; ++k) {
		snprintf(t1, sizeof(t1), tx, sets[k][0], sets[k][0]);
		snprintf(t2, sizeof(t2), tx, sets[k][1], sets[k][1]);
		snprintf(txs, sizeof(txs), "%s,%s", t1, t2);
		snprintf(gbt, sizeof(gbt), gbt_fmt, 0, 0, 0, txs);
		json_t *j = json_loads(gbt, 0, &error);
		datum_test(j != NULL);
		T_DATUM_TEMPLATE_DATA *t = j ? datum_gbt_parser(j) : NULL;
		datum_test(t != NULL);
		if (t) memcpy(hashes[k], t->txn_content_hash, 32);
		else memset(hashes[k], 0, 32);
		json_decref(j);
	}
	datum_test(memcmp(hashes[0], zero, 32) != 0);           // set by the parser
	datum_test(memcmp(hashes[0], hashes[1], 32) == 0);      // same transactions
	datum_test(memcmp(hashes[0], hashes[2], 32) != 0);      // a different transaction
	datum_test(memcmp(hashes[0], hashes[3], 32) != 0);      // a different order
}

void datum_blocktemplates_tests(void) {
	datum_gbt_rules_blake2b_tests();
	datum_blocktemplates_abw_mode_tests();
	datum_template_content_hash_tests();
}
