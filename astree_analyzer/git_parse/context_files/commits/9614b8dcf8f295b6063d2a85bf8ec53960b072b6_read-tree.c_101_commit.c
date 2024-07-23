/* Commit: 9614b8dcf8f295b6063d2a85bf8ec53960b072b6
 * File: read-tree.c
 * Line: 101
 * Code: 
 */

	}
	if (!write_cache(newfd, active_cache, active_nr) && !rename(".dircache/index.lock", ".dircache/index"))
		return 0;
