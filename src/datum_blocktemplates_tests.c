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
#include "datum_utils.h"

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
	
	gbt = json_loads("{\"rules\":[\"!blake2b-extra\",\"xblake2b\"]}", 0, &error);
	datum_test(gbt != NULL);
	datum_test(!datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
	
	datum_test(!datum_gbt_rules_want_blake2b(NULL));
	gbt = json_object();
	datum_test(gbt != NULL);
	datum_test(!datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
	
	memcpy(datum_config.mining_pow_algorithm, saved_pow, sizeof(saved_pow));
}
void datum_blocktemplates_tests(void) {
	datum_gbt_rules_blake2b_tests();
}
