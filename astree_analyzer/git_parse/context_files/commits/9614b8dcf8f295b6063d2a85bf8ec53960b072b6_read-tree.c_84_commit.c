/* Commit: 9614b8dcf8f295b6063d2a85bf8ec53960b072b6
 * File: read-tree.c
 * Line: 84
 * Code: 			if (read_cache() < 0) {
 */

if (read_cache() < 0) {
				fprintf(stderr, "read-tree: corrupt directory cache\n");
				goto out;
			}