/* Commit: 9614b8dcf8f295b6063d2a85bf8ec53960b072b6
 * File: update-cache.c
 * Line: 245
 * Code: 	if (newfd < 0) {
 */

if (newfd < 0) {
		perror("unable to create new cachefile");
		return -1;
	}