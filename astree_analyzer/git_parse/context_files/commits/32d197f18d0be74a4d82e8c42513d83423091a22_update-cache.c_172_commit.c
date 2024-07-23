/* Commit: 32d197f18d0be74a4d82e8c42513d83423091a22
 * File: update-cache.c
 * Line: 172
 * Code: 	 * If the length has changed, there's no point in trying
 */

static struct cache_entry *refresh_entry(struct cache_entry *ce)
{
	struct stat st;
	struct cache_entry *updated;
	int changed, size;

	if (stat(ce->name, &st) < 0)
		return NULL;

	changed = cache_match_stat(ce, &st);
	if (!changed)
		return ce;

	/*
	 * If the length has changed, there's no point in trying
	 * to refresh the entry - it's not going to match
	 */
	if (changed & (DATA_CHANGED | MODE_CHANGED))
		return NULL;

	if (compare_data(ce))
		return NULL;

	size = ce_size(ce);
	updated = malloc(size);
	memcpy(updated, ce, size);
	fill_stat_cache_info(updated, &st);
	return updated;
}