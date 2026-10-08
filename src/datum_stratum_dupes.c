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
 * Copyright (c) 2024-2026 Bitcoin Ocean, LLC, Jason Hughes, and individual contributors
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
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>

#include "datum_stratum_dupes.h"
#include "datum_stratum.h"
#include "datum_conf.h"
#include "datum_utils.h"

static inline
uint16_t datum_stratum_dupes_bucket(const uint8_t * const share_hash) {
	return (uint16_t)(share_hash[0] | ((uint16_t)share_hash[1] << 8));
}

void datum_stratum_dupes_init(void *sdata_v) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = sdata_v;
	T_DATUM_STRATUM_DUPES *dupes = NULL;
	sdata->dupes = calloc(  sizeof(T_DATUM_STRATUM_DUPES) + 16, 1 );
	if (!sdata->dupes) {
		DLOG_FATAL("Could not allocate RAM for dupe struct (small one, %lu bytes)", (unsigned long)sizeof(T_DATUM_STRATUM_DUPES) + 16);
		panic_from_thread(__LINE__);
		return;
	}
	
	dupes = sdata->dupes;
	
	dupes->max_items = datum_expected_n_global_nonstale_shares(&datum_config);
	if (!dupes->max_items) {
		DLOG_FATAL("Dupe struct requires more RAM than we have virtual memory space!");
		panic_from_thread(__LINE__);
		return;
	}
	
	dupes->ptr = calloc(dupes->max_items, sizeof(T_DATUM_STRATUM_DUPE_ITEM));
	if (!dupes->ptr) {
		DLOG_FATAL("Could not allocate RAM for dupe struct (big one, %zu * %zu bytes)", dupes->max_items, sizeof(T_DATUM_STRATUM_DUPE_ITEM));
		panic_from_thread(__LINE__);
		return;
	}
	
	dupes->current_items = 0;
	
	DLOG_DEBUG("Initialized dupe check thread data. %zu bytes of RAM used for %zu max entries @ %p for %p", dupes->max_items * sizeof(T_DATUM_STRATUM_DUPE_ITEM), dupes->max_items, dupes, sdata);
	
	return;
}

int datum_stratum_dupes_cleanup_sort_compare(const void *a, const void *b) {
	const T_DATUM_STRATUM_DUPE_ITEM *item1 = a;
	const T_DATUM_STRATUM_DUPE_ITEM *item2 = b;
	
	if (item1 == NULL && item2 == NULL) return 0;
	if (item1 == NULL) return 1;
	if (item2 == NULL) return -1;
	
	if (item1->job_tsms > item2->job_tsms) return -1;
	if (item1->job_tsms < item2->job_tsms) return 1;
	return 0;
}

size_t find_first_less_than(T_DATUM_STRATUM_DUPE_ITEM * const ptr, const size_t max_items, const uint64_t given_tsms) {
	assert(max_items > 0);
	size_t low = 0;
	size_t high_pp = max_items;
	size_t result = (size_t)-1;
	uint64_t tsms;
	
	while (low < high_pp) {
		size_t mid = low + (high_pp - low - 1) / 2;
		
		// sanity
		if (mid < 0) mid = 0;
		if (mid > (max_items-1)) mid = max_items-1;
		
		// more sanity
		tsms = ptr[mid].job_tsms;
		
		// bsearch until we find the first entry < given
		if (tsms < given_tsms) {
			result = mid;
			high_pp = mid;
		} else {
			low = mid + 1;
		}
	}
	
	return result;
}

void datum_stratum_dupes_expand(T_DATUM_STRATUM_DUPES *dupes) {
	T_DATUM_STRATUM_DUPE_ITEM *new_ptr;
	size_t new_max = ((dupes->max_items * 125)/100);
	new_ptr = realloc(dupes->ptr, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * new_max);
	if (!new_ptr) {
		DLOG_FATAL("Could not reallocate dupes ptr %p of %zu items to %zu items!", dupes->ptr, dupes->max_items, new_max);
		panic_from_thread(__LINE__);
		return;
	}
	memset(&new_ptr[dupes->max_items], 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * (new_max - dupes->max_items));
	DLOG_DEBUG("INFO: Had to allocate more RAM to duplicate share checking for thread.  %zu to %zu items (%zu bytes)", dupes->max_items, new_max, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * new_max);
	
	dupes->max_items = new_max;
	dupes->ptr = new_ptr;
	
	// always needs reoganizing after this... do externally.
}

void datum_stratum_dupes_reorganize(T_DATUM_STRATUM_DUPES *dupes) {
	size_t i;
	T_DATUM_STRATUM_DUPE_ITEM *q,*p=NULL;
	
	for(i=0;i<dupes->max_items;i++) {
		// we'll use job_tsms as an indicator, since obviously it can't be zero
		if (dupes->ptr[i].job_tsms == 0) break;
		
		const uint16_t bucket = datum_stratum_dupes_bucket(dupes->ptr[i].share_hash);
		if (!dupes->index[bucket]) {
			// easy. this is the first
			dupes->index[bucket] = &dupes->ptr[i];
			dupes->ptr[i].next = NULL;
			continue;
		}
		
		q = dupes->index[bucket];
		p = NULL;
		do {
			int cmp = memcmp(q->share_hash, dupes->ptr[i].share_hash, sizeof(q->share_hash));
			if (cmp > 0) {
				if (p) {
					// insert after p
					p->next = &dupes->ptr[i];
				} else {
					// insert as first entry, before this one
					dupes->index[bucket] = &dupes->ptr[i];
				}
				dupes->ptr[i].next = q;
				break;
			}
			
			// this should be safe here, even though we haven't cleaned up all the old pointers
			// the reason is that nothing we having cleaned should have ended up in the index yet
			p = q;
			if (!q->next) {
				// ended up at the last entry without finding one greater than me... add to the end
				q->next = &dupes->ptr[i];
				dupes->ptr[i].next = NULL;
				q = NULL;
				break;
			} else {
				q = q->next;
			}
		} while(q);
	}
	
	dupes->current_items = i;
	
	// should be all straightened out now
}

void datum_stratum_dupes_cleanup(T_DATUM_STRATUM_DUPES *dupes, bool full_wipe) {
	size_t i;
	
	if (full_wipe) {
		// we're just cleaning up after a new block or whatever
		memset(dupes->ptr, 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * dupes->max_items);
		// The buckets have to go with the items they point at. Leaving them meant every
		// bucket still named a slot that had just been zeroed and was about to be handed
		// out again to a new entry, so the first share on such a bucket could link a slot
		// to itself and the next walk of that chain would never terminate. Nothing calls
		// this with full_wipe today, which is the only reason that has not been seen.
		memset(dupes->index, 0, sizeof(dupes->index));
		dupes->current_items = 0;
		return;
	}
	
	// Somewhat expensive cleanup of dupes...
	// first, sort the full dupe list by the dupe's stratum job timestamp, decending... which is trickyish
	// then, bsearch find the index of the first item with a job timestamp that is from a stale job
	// if there are entries after it, we're good and we can prune those
	// fix the linked list
	
	// this breaks all links. we'll need to reconstruct them!
	qsort(dupes->ptr, dupes->max_items, sizeof(T_DATUM_STRATUM_DUPE_ITEM), datum_stratum_dupes_cleanup_sort_compare);
	
	// links all broken, so wipe out the starting table
	memset(dupes->index, 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM *) * 65536);
	
	const uint64_t job_stale_seconds = datum_config.stratum_v1_share_stale_seconds + datum_config.bitcoind_work_update_seconds;
	
	// find the first stale index
	i = find_first_less_than(dupes->ptr, dupes->max_items, current_time_millis() - (uint64_t)(job_stale_seconds * 1000));
	
	if ((i == (size_t)-1) || (i == dupes->max_items-1)) {
		// none of the items are stale...
		datum_stratum_dupes_expand(dupes);
	} else {
		// ok, we want to free up at least 5% of the entries, otherwise we'll be right back here wasting CPU time
		if (i < ((dupes->max_items * 95)/100)) {
			// at least 5% are good
			// clear out the stales...
			dupes->current_items = i;
			memset(&dupes->ptr[i], 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * (dupes->max_items - i));
		} else {
			// < 5% are freeable... we just need more RAM.
			datum_stratum_dupes_expand(dupes);
		}
	}
	
	// fix all the links in our now either expanded or cleaned dupe list
	datum_stratum_dupes_reorganize(dupes);
}

T_DATUM_STRATUM_DUPE_ITEM *datum_stratum_add_new_dupe(T_DATUM_STRATUM_DUPES * const dupes, const uint8_t * const share_hash, const uint64_t job_tsms, T_DATUM_STRATUM_DUPE_ITEM * const insert_after) {
	T_DATUM_STRATUM_DUPE_ITEM *i;

	// The caller makes room before it walks the list, so this is a bug rather than a
	// full table. Refusing the entry loses one share's dupe protection; writing past
	// the end of the array corrupts the heap.
	if (dupes->current_items >= dupes->max_items) {
		// Once per run, not once per share. This fires on the share path, so a bug that
		// made it reachable would otherwise write a line per share submitted.
		static bool reported = false;
		if (!reported) {
			reported = true;
			DLOG_ERROR("Dupe table full at insert (%zu/%zu); dropping the entry rather than writing past it. This should not be reachable; please report it.", dupes->current_items, dupes->max_items);
		}
		return NULL;
	}

	i = &dupes->ptr[dupes->current_items];
	if (!i) {
		DLOG_FATAL("Could not add entry to dupe table!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	memcpy(i->share_hash, share_hash, sizeof(i->share_hash));
	i->job_tsms = job_tsms;
	if (!insert_after) {
		// is a new entry
		i->next = NULL;
	} else {
		i->next = insert_after->next;
		insert_after->next = i;
	}
	dupes->current_items++;

	// The cleanup that used to be here ran between taking this pointer and returning it,
	// and both of the things it can do invalidate it: the sort moves every item, and the
	// expand reallocates the array. The caller stores what it gets back into the bucket
	// index, so the index ended up holding a pointer into the freed array and the next
	// share on that nonce read it. It has moved to the top of datum_stratum_check_for_dupe,
	// which is the only place there is no insertion point to invalidate.

	return i;
}

bool datum_stratum_check_for_dupe(T_DATUM_STRATUM_THREADPOOL_DATA *t, const uint8_t * const share_hash, const uint64_t job_tsms) {
	// check if a share is a dupe
	// if so, say so
	// if not, add to the
	T_DATUM_STRATUM_DUPES *dupes;
	const uint16_t bucket = datum_stratum_dupes_bucket(share_hash);
	
	assert(job_tsms);  // 0 job_tsms indicates empty slots
	
	T_DATUM_STRATUM_DUPE_ITEM *i, *p = NULL;
	
	if (!t) {
		DLOG_FATAL("Threadpool data not available?!");
		panic_from_thread(__LINE__);
		return true;
	}
	
	dupes = t->dupes;

	// Make room before reading anything out of the table. Everything below this line
	// either holds a pointer into the array or an insertion point in a bucket, and a
	// cleanup invalidates both, so this is the last moment it can safely run.
	if (dupes->current_items >= dupes->max_items) {
		datum_stratum_dupes_cleanup(dupes, false);
	}

	if (dupes->index[bucket] == NULL) {
		// first of its kind!
		// not a duplicate
		// add the new first entry!
		dupes->index[bucket] = datum_stratum_add_new_dupe(dupes, share_hash, job_tsms, NULL);
		return false;
	}
	
	// ok, there's an entry.  go through the list
	i = dupes->index[bucket];
	
	do {
		int cmp = memcmp(i->share_hash, share_hash, sizeof(i->share_hash));
		if (cmp > 0) {
			// we've reached a hash higher than ours, so we can't be a dupe
			// we need to keep the list in order, so we need to insert ourselves before this entry (so, the previous entry)
			if (p) {
				datum_stratum_add_new_dupe(dupes, share_hash, job_tsms, p);
			} else {
				// we need to replace the first item in a list, so... let's make a new entry
				p = datum_stratum_add_new_dupe(dupes, share_hash, job_tsms, NULL);
				// A refused entry leaves the bucket as it was rather than unlinking it
				if (!p) return false;
				dupes->index[bucket] = p;
				p->next = i;
			}
			//LOG_PRINTF("DEBUG: Not dupe");
			return false;
		}
		
		if (cmp == 0) {
			// ok, this is a duplicate :(
			return true;
		}
		
		// store the current ptr for the next loop
		p = i;
		
		// setup i to be the next link
		// if it's the end of the chain, this will be NULL and the loop will break
		i = i->next;
	} while (i);
	
	// we reached the end of the list, and haven't found a dupe
	// means that all of the hashes in the list are lower than us
	// so we should be safe to insert ourselves on to the end of the list and return
	datum_stratum_add_new_dupe(dupes, share_hash, job_tsms, p);
	return false;
}

#if 0

void datum_stratum_dupes_codetest(void) {
	int i;
	uint64_t t;
	bool r;
	unsigned char en[12] = { 0 };
	int stratum_job_next = 0;
	T_DATUM_STRATUM_JOB *stratum_job_list;
	unsigned int nonce;
	
	// make a fake thread pool
	T_DATUM_STRATUM_THREADPOOL_DATA tp;
	
	datum_stratum_dupes_init(&tp);
	T_DATUM_STRATUM_DUPES *dupes = tp.dupes;
	
	stratum_job_list = calloc(MAX_STRATUM_JOBS,sizeof(T_DATUM_STRATUM_JOB));
	
	t = current_time_millis() - (datum_config.stratum_v1_share_stale_seconds*2000);
	
	// fill stratum jobs with garbage tsms
	for(i=0;i<MAX_STRATUM_JOBS;i++) {
		global_cur_stratum_jobs[i] = &stratum_job_list[stratum_job_next];
		stratum_job_next++;
		if (stratum_job_next == MAX_STRATUM_JOBS) stratum_job_next = 0;
		global_cur_stratum_jobs[i]->tsms = t;
		t+=1000000000;
	}
	
	for(i=0;i<datum_expected_n_global_nonstale_shares(&datum_config)*80;i++) {
		en[0]=i%256;
		en[7]=en[0]^0xAA;
		nonce = ((i&0xFFFF)<<16)|(((i>>2)&0xFFFF)^0xFFFF);
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		if (!r) {
			DLOG_DEBUG("MISSED A DUPE 1 - %d - %8.8x - %d / %4.4x",i, nonce , nonce & 0xFFFF, nonce & 0xFFFF);
		}
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		if (!r) {
			DLOG_DEBUG("MISSED A DUPE 2 - %d - %8.8x - %d / %4.4x",i, nonce , nonce & 0xFFFF, nonce & 0xFFFF);
		}
	}
	
	r = datum_stratum_check_for_dupe(&tp, 0xdeadc0de, 12, t, 0x20000001, &en[0]);
	DLOG_DEBUG("B %d %zu %zu",r?1:0, dupes->current_items, dupes->max_items);
	
	uint64_t starttsms, endtsms;
	starttsms = current_time_millis();
	for(i=0;i<datum_expected_n_global_nonstale_shares(&datum_config)*8;i++) {
		en[0]=i%256;
		en[7]=en[0]^0xAA;
		nonce = ((i&0xFFFF)<<16)|(((i>>2)&0xFFFF)^0xFFFF);
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		if (!r) {
			DLOG_DEBUG("MISSED A DUPE 3 - %d - %8.8x - %d / %4.4x",i, nonce , nonce & 0xFFFF, nonce & 0xFFFF);
		}
	}
	endtsms = current_time_millis();
	DLOG_DEBUG("%zu dupe checks took %"PRIu64" miliseconds", datum_expected_n_global_nonstale_shares(&datum_config)*80, endtsms-starttsms);
	
	free(stratum_job_list);
}

#endif
