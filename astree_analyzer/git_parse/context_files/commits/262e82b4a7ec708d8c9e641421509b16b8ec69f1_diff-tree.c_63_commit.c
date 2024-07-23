/* Commit: 262e82b4a7ec708d8c9e641421509b16b8ec69f1
 * File: diff-tree.c
 * Line: 63
 * Code: 	if (recursive && S_ISDIR(mode1) && S_ISDIR(mode2)) {
 */

if (recursive && S_ISDIR(mode1) && S_ISDIR(mode2)) {
		int retval;
		int baselen = strlen(base);
		char *newbase = malloc(baselen + pathlen1 + 2);
		memcpy(newbase, base, baselen);
		memcpy(newbase + baselen, path1, pathlen1);
		memcpy(newbase + baselen + pathlen1, "/", 2);
		retval = diff_tree_sha1(sha1, sha2, newbase);
		free(newbase);
		return retval;
	}