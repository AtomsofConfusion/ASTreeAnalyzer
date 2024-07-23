/* Commit: 59c1e249808c6ba38194733fa00efddb9e0eb488
 * File: fsck-cache.c
 * Line: 51
 * Code: /* "parent " + <hex sha1> + '\n' */
 */

{
		if (get_sha1_hex(data + 7, parent_sha1) < 0)
			return -1;
		mark_needs_sha1(sha1, "commit", parent_sha1);
		data += 7 + 40 + 1; 	/* "parent " + <hex sha1> + '\n' */
	}