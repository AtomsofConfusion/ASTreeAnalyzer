/* Commit: 76e7f4ec485f24b167b76db046dc2ca4562debd4
 * File: read-cache.c
 * Line: 369
 * Code: // avoid gcc warning
 */

int read_cache(void)
{
	int fd, i;
	struct stat st;
	unsigned long size, offset;
	void *map;
	struct cache_header *hdr;

	errno = EBUSY;
	if (active_cache)
		return error("more than one cachefile");
	errno = ENOENT;
	sha1_file_directory = getenv(DB_ENVIRONMENT);
	if (!sha1_file_directory)
		sha1_file_directory = DEFAULT_DB_ENVIRONMENT;
	if (access(sha1_file_directory, X_OK) < 0)
		return error("no access to SHA1 file directory");
	fd = open(".dircache/index", O_RDONLY);
	if (fd < 0)
		return (errno == ENOENT) ? 0 : error("open failed");

	size = 0; // avoid gcc warning
	map = (void *)-1;
	if (!fstat(fd, &st)) {
		size = st.st_size;
		errno = EINVAL;
		if (size >= sizeof(struct cache_header))
			map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	}
	close(fd);
	if (-1 == (int)(long)map)
		return error("mmap failed");

	hdr = map;
	if (verify_hdr(hdr, size) < 0)
		goto unmap;

	active_nr = hdr->entries;
	active_alloc = alloc_nr(active_nr);
	active_cache = calloc(active_alloc, sizeof(struct cache_entry *));

	offset = sizeof(*hdr);
	for (i = 0; i < hdr->entries; i++) {
		struct cache_entry *ce = map + offset;
		offset = offset + ce_size(ce);
		active_cache[i] = ce;
	}
	return active_nr;

unmap:
	munmap(map, size);
	errno = EINVAL;
	return error("verify header failed");
}