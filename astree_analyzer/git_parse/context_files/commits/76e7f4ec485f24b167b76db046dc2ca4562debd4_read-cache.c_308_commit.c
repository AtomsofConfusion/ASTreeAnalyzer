/* Commit: 76e7f4ec485f24b167b76db046dc2ca4562debd4
 * File: read-cache.c
 * Line: 308
 * Code: 	if (pos < 0) {
 */

if (pos < 0) {
		active_cache[-pos-1] = ce;
		return 0;
	}