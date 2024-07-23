/* Commit: 9614b8dcf8f295b6063d2a85bf8ec53960b072b6
 * File: read-tree.c
 * Line: 80
 * Code: 			if (active_cache) {
 */

if (active_cache) {
				fprintf(stderr, "read-tree: cannot merge old cache on top of new\n");
				goto out;
			}