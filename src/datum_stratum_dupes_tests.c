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

#include <stdlib.h>

#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_utils.h"

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

void datum_stratum_dupes_tests(void) {
	datum_pow_sia_dupe_tests();
}
