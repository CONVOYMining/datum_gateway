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

void datum_blocktemplates_tests(void) {
	datum_gbt_rules_blake2b_tests();
	datum_blocktemplates_abw_mode_tests();
}
