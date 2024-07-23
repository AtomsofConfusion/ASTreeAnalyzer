/* Commit: 9614b8dcf8f295b6063d2a85bf8ec53960b072b6
 * File: read-tree.c
 * Line: 104
 * Code: 	exit(1);
 */

int main(int argc, char **argv)
{
	int i, newfd;
	unsigned char sha1[20];

	newfd = open(".dircache/index.lock", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (newfd < 0)
		usage("unable to create new cachefile");

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		/* "-m" stands for "merge" current directory cache */
		if (!strcmp(arg, "-m")) {
			if (active_cache) {
				fprintf(stderr, "read-tree: cannot merge old cache on top of new\n");
				goto out;
			}
			if (read_cache() < 0) {
				fprintf(stderr, "read-tree: corrupt directory cache\n");
				goto out;
			}
			continue;
		}
		if (get_sha1_hex(arg, sha1) < 0) {
			fprintf(stderr, "read-tree [-m] <sha1>\n");
			goto out;
		}
		if (read_tree(sha1, "", 0) < 0) {
			fprintf(stderr, "failed to unpack tree object %s\n", arg);
			goto out;
		}
	}
	if (!write_cache(newfd, active_cache, active_nr) && !rename(".dircache/index.lock", ".dircache/index"))
		return 0;

out:
	unlink(".dircache/index.lock");
	exit(1);
}