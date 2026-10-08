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

#include <stdint.h>
#include <stdlib.h>

#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_utils.h"

static void datum_pow_dupe_tests(void) {
	T_DATUM_STRATUM_DUPE_ITEM items[8] = {0};
	T_DATUM_STRATUM_DUPES * const dupes = calloc(1, sizeof(*dupes));
	T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
	uint8_t share_hash_low[28] = {0};
	uint8_t share_hash_high[28] = {1};
	
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
	datum_test(!datum_stratum_check_for_dupe(thread_data, share_hash_low, /*job_tsms=*/1));
	datum_test(!datum_stratum_check_for_dupe(thread_data, share_hash_high, /*job_tsms=*/1));
	datum_test(datum_stratum_check_for_dupe(thread_data, share_hash_low, /*job_tsms=*/2));
	datum_test(datum_stratum_check_for_dupe(thread_data, share_hash_high, /*job_tsms=*/2));
	free(dupes);
	free(thread_data);
}

// Fill the table past max_items, which is the only way the cleanup/expand path runs.
// Nothing above reaches it: that test has 8 slots and inserts 2.
static void datum_dupe_table_fill_tests(void) {
	const int saved_clients = datum_config.stratum_v1_max_clients_per_thread;
	const int saved_shares = datum_config.stratum_v1_vardiff_target_shares_min;
	const int saved_stale = datum_config.stratum_v1_share_stale_seconds;

	// max_items = clients * shares_min * (stale/60) * 16, so this is a 16 slot table
	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;

	T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
	datum_test(thread_data != NULL);
	if (!thread_data) return;
	datum_stratum_dupes_init(thread_data);

	const uint64_t now = current_time_millis();
	uint8_t share_hash[28] = {0};
	
	// Distinct low 16 bits, so every share lands in a bucket of its own and each insert
	// is the "first nonce of its kind" case.
	for (int i = 0; i < 64; ++i) {
		share_hash[1] = (uint8_t)i;
		datum_test(!datum_stratum_check_for_dupe(thread_data, share_hash, /*job_tsms=*/now));
	}

	// The table has to have actually grown, or nothing above went through the path this
	// test exists for and the assertions below prove nothing.
	T_DATUM_STRATUM_DUPES * const dupes = thread_data->dupes;
	datum_test(dupes->max_items > 16);
	datum_test(dupes->current_items <= dupes->max_items);

	// Every one of those is a duplicate now. Re-probing walks each bucket from its index
	// entry, which is where a pointer left over from before a reallocation is read.
	for (int i = 0; i < 64; ++i) {
		share_hash[1] = (uint8_t)i;
		datum_test(datum_stratum_check_for_dupe(thread_data, share_hash, /*job_tsms=*/now));
	}

	free(dupes->ptr);
	free(thread_data->dupes);
	free(thread_data);

	datum_config.stratum_v1_max_clients_per_thread = saved_clients;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares;
	datum_config.stratum_v1_share_stale_seconds = saved_stale;
}

// Every pointer reachable from the bucket index must name a live entry, and no chain may
// loop. A chain that loops never terminates in datum_stratum_check_for_dupe, which runs on
// the stratum thread with that thread's clients waiting on it.
static void datum_dupe_index_is_sound(const T_DATUM_STRATUM_DUPES *dupes) {
	for (int b = 0; b < 65536; ++b) {
		const T_DATUM_STRATUM_DUPE_ITEM *i = dupes->index[b];
		int walked = 0;
		while (i) {
			const ptrdiff_t slot = i - dupes->ptr;
			// Named rather than asserted inline, because datum_test reports the expression
			// it was given and these are what the reader wants to see in a failure
			const bool bucket_points_at_a_live_entry =
				slot >= 0 && slot < dupes->current_items;
			if (!datum_test(bucket_points_at_a_live_entry)) return;
			const bool bucket_chain_terminates = ++walked <= dupes->current_items;
			if (!datum_test(bucket_chain_terminates)) return;
			i = i->next;
		}
	}
}

// The other half of the cleanup, and the half a gateway actually reaches: entries old
// enough to age out are pruned rather than the array being grown. The prune sorts the
// array, which moves every entry, so an insertion point taken before it is stale after it
// in the same way a reallocation makes one stale.
static void datum_dupe_table_prune_tests(void) {
	const int saved_clients = datum_config.stratum_v1_max_clients_per_thread;
	const int saved_shares = datum_config.stratum_v1_vardiff_target_shares_min;
	const int saved_stale = datum_config.stratum_v1_share_stale_seconds;

	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;

	T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
	datum_test(thread_data != NULL);
	if (!thread_data) return;
	datum_stratum_dupes_init(thread_data);
	T_DATUM_STRATUM_DUPES * const dupes = thread_data->dupes;

	uint64_t fresh_tsms = current_time_millis();
	uint64_t old_tsms = current_time_millis() - 600000;
	
	uint8_t share_hash[28] = {0};
	
	// Mostly stale, so the cleanup frees well over its 5% and takes the prune path
	for (int i = 0; i < 256; ++i) {
		share_hash[1] = (uint8_t)i;
		const uint64_t job_tsms = (i % 8) ? old_tsms : fresh_tsms;
		datum_stratum_check_for_dupe(thread_data, share_hash, job_tsms);
		datum_dupe_index_is_sound(dupes);
	}

	free(dupes->ptr);
	free(thread_data->dupes);
	free(thread_data);

	datum_config.stratum_v1_max_clients_per_thread = saved_clients;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares;
	datum_config.stratum_v1_share_stale_seconds = saved_stale;
}

// Many cleanup cycles of both kinds, against the invariant the insert now relies on:
// datum_stratum_check_for_dupe must leave room for the next entry, every time. If it ever
// does not, datum_stratum_add_new_dupe refuses a share's dupe record and says so in the
// log, which is a thing an operator should never see.
//
// Both kinds matter because they fail differently. A prune sorts the array in place and an
// expand reallocates it, and before the fix each left a different flavour of stale pointer
// in the bucket index.
static void datum_dupe_table_cycle_tests(void) {
	const int saved_clients = datum_config.stratum_v1_max_clients_per_thread;
	const int saved_shares = datum_config.stratum_v1_vardiff_target_shares_min;
	const int saved_stale = datum_config.stratum_v1_share_stale_seconds;

	datum_config.stratum_v1_max_clients_per_thread = 2;
	datum_config.stratum_v1_vardiff_target_shares_min = 2;
	datum_config.stratum_v1_share_stale_seconds = 60;

	T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
	datum_test(thread_data != NULL);
	if (!thread_data) return;
	datum_stratum_dupes_init(thread_data);
	T_DATUM_STRATUM_DUPES * const dupes = thread_data->dupes;
	const size_t initial_max = dupes->max_items;

	bool saw_expand = false;
	uint8_t share_hash[28] = {0};

	for (int i = 0; i < 20000; ++i) {
		// Jobs age as the run goes on, so cleanups alternate between having plenty to
		// prune and having nothing to prune and needing to grow.
		const uint64_t now = current_time_millis();
		uint64_t job_tsms = now;
		switch (i & 3) {
			case 2:
				if (i % 3) job_tsms -= 600000;
				break;
			case 3:
				if (i % 7) job_tsms -= 600000;
				break;
		}

		const uint16_t bucket = (uint16_t)(((uint64_t)i * 2654435761u) ^ ((uint64_t)i << 24));
		share_hash[0] = (uint8_t)bucket;
		share_hash[1] = (uint8_t)(bucket >> 8);
		share_hash[8] = (uint8_t)i;
		share_hash[16] = (uint8_t)(i >> 8);

		// A table that is not yet full cannot clean up during the call, so a share that is
		// not a duplicate has to become exactly one new entry. Anything else means the
		// insert refused it, which is the only way the fix can go wrong quietly: the share
		// is still accepted, but nothing remembers it and a real resubmission slips past.
		const size_t before = dupes->current_items;
		const bool had_room = before < dupes->max_items;
		const bool dupe = datum_stratum_check_for_dupe(thread_data, share_hash, job_tsms);
		if (had_room && !dupe) {
			const bool the_new_share_became_an_entry =
				dupes->current_items == before + 1;
			datum_test(the_new_share_became_an_entry);
		}

		// Never past the end of the array, cleanup or no cleanup
		const bool entries_fit_the_array = dupes->current_items <= dupes->max_items;
		datum_test(entries_fit_the_array);
		if (dupes->max_items > initial_max) saw_expand = true;
	}

	datum_dupe_index_is_sound(dupes);
	datum_test(saw_expand);

	free(dupes->ptr);
	free(thread_data->dupes);
	free(thread_data);

	datum_config.stratum_v1_max_clients_per_thread = saved_clients;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares;
	datum_config.stratum_v1_share_stale_seconds = saved_stale;
}

void datum_stratum_dupes_tests(void) {
	datum_pow_dupe_tests();
	datum_dupe_table_fill_tests();
	datum_dupe_table_prune_tests();
	datum_dupe_table_cycle_tests();
}
