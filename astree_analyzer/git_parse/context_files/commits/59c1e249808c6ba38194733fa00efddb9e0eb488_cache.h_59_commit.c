/* Commit: 59c1e249808c6ba38194733fa00efddb9e0eb488
 * File: cache.h
 * Line: 59
 * Code: 	unsigned char name[0];
 */

struct cache_entry {
	struct cache_time ctime;
	struct cache_time mtime;
	unsigned int st_dev;
	unsigned int st_ino;
	unsigned int st_mode;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned int st_size;
	unsigned char sha1[20];
	unsigned short namelen;
	unsigned char name[0];
}