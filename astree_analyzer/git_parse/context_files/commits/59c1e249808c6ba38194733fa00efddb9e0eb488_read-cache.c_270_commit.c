/* Commit: 59c1e249808c6ba38194733fa00efddb9e0eb488
 * File: read-cache.c
 * Line: 270
 * Code: 		if (size > sizeof(struct cache_header))
 */

{
		map = NULL;
		size = st.st_size;
		errno = EINVAL;
		if (size > sizeof(struct cache_header))
			map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	}