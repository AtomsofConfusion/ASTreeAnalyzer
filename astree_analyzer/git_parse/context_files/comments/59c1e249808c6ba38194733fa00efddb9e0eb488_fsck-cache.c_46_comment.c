/* Commit: 59c1e249808c6ba38194733fa00efddb9e0eb488
 * File: fsck-cache.c
 * Line: 46
 * Code: /* "tree " + <hex sha1> + '\n' */
 */

static int fsck_commit(unsigned char *sha1, void *data, unsigned long size)
{
	unsigned char tree_sha1[20];
	unsigned char parent_sha1[20];

	if (memcmp(data, "tree ", 5))
		return -1;
	if (get_sha1_hex(data + 5, tree_sha1) < 0)
		return -1;
	mark_needs_sha1(sha1, "tree", tree_sha1);
	data += 5 + 40 + 1;	/* "tree " + <hex sha1> + '\n' */
	while (!memcmp(data, "parent ", 7)) {
		if (get_sha1_hex(data + 7, parent_sha1) < 0)
			return -1;
		mark_needs_sha1(sha1, "commit", parent_sha1);
		data += 7 + 40 + 1; 	/* "parent " + <hex sha1> + '\n' */
	}
	return 0;
}