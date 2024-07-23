/* Commit: 76e7f4ec485f24b167b76db046dc2ca4562debd4
 * File: read-cache.c
 * Line: 292
 * Code: 	if (pos < 0) {
 */

if (pos < 0) {
		pos = -pos-1;
		active_nr--;
		if (pos < active_nr)
			memmove(active_cache + pos, active_cache + pos + 1, (active_nr - pos - 1) * sizeof(struct cache_entry *));
	}