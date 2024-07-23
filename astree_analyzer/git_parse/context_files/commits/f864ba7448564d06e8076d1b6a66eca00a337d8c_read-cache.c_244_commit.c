/* Commit: f864ba7448564d06e8076d1b6a66eca00a337d8c
 * File: read-cache.c
 * Line: 244
 * Code: 
 */

{
		void *map;

		if (errno != EEXIST)
			return -1;
#ifndef COLLISION_CHECK
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			return -1;
		map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (map == MAP_FAILED)
			return -1;
		if (memcmp(buf, map, size))
			return error("SHA1 collision detected!"
					" This is bad, bad, BAD!\a\n");
#endif
		return 0;
	}