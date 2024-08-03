#include "cache.h"
#include "commit.h"
#include "pack.h"
#include "tag.h"
#include "blob.h"
#include "http.h"
#include "refs.h"
#include "diff.h"
#include "revision.h"
#include "exec_cmd.h"
#include "remote.h"
#include "list-objects.h"

#include <expat.h>

static const char http_push_usage[] =
"git http-push [--all] [--dry-run] [--force] [--verbose] <remote> [<head>...]\n";

#ifndef XML_STATUS_OK
enum XML_Status {
  XML_STATUS_OK = 1,
  XML_STATUS_ERROR = 0
};
#define XML_STATUS_OK    1
#define XML_STATUS_ERROR 0
#endif

#define PREV_BUF_SIZE 4096
#define RANGE_HEADER_SIZE 30

/* DAV methods */
#define DAV_LOCK "LOCK"
#define DAV_MKCOL "MKCOL"
#define DAV_MOVE "MOVE"
#define DAV_PROPFIND "PROPFIND"
#define DAV_PUT "PUT"
#define DAV_UNLOCK "UNLOCK"
#define DAV_DELETE "DELETE"

/* DAV lock flags */
#define DAV_PROP_LOCKWR (1u << 0)
#define DAV_PROP_LOCKEX (1u << 1)
#define DAV_LOCK_OK (1u << 2)

/* DAV XML properties */
#define DAV_CTX_LOCKENTRY ".multistatus.response.propstat.prop.supportedlock.lockentry"
#define DAV_CTX_LOCKTYPE_WRITE ".multistatus.response.propstat.prop.supportedlock.lockentry.locktype.write"
#define DAV_CTX_LOCKTYPE_EXCLUSIVE ".multistatus.response.propstat.prop.supportedlock.lockentry.lockscope.exclusive"
#define DAV_ACTIVELOCK_OWNER ".prop.lockdiscovery.activelock.owner.href"
#define DAV_ACTIVELOCK_TIMEOUT ".prop.lockdiscovery.activelock.timeout"
#define DAV_ACTIVELOCK_TOKEN ".prop.lockdiscovery.activelock.locktoken.href"
#define DAV_PROPFIND_RESP ".multistatus.response"
#define DAV_PROPFIND_NAME ".multistatus.response.href"
#define DAV_PROPFIND_COLLECTION ".multistatus.response.propstat.prop.resourcetype.collection"

/* DAV request body templates */
#define PROPFIND_SUPPORTEDLOCK_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:propfind xmlns:D=\"DAV:\">\n<D:prop xmlns:R=\"%s\">\n<D:supportedlock/>\n</D:prop>\n</D:propfind>"
#define PROPFIND_ALL_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:propfind xmlns:D=\"DAV:\">\n<D:allprop/>\n</D:propfind>"
#define LOCK_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:lockinfo xmlns:D=\"DAV:\">\n<D:lockscope><D:exclusive/></D:lockscope>\n<D:locktype><D:write/></D:locktype>\n<D:owner>\n<D:href>mailto:%s</D:href>\n</D:owner>\n</D:lockinfo>"

#define LOCK_TIME 600
#define LOCK_REFRESH 30

/* bits #0-15 in revision.h */

#define LOCAL    (1u<<16)
#define REMOTE   (1u<<17)
#define FETCHING (1u<<18)
#define PUSHING  (1u<<19)

/* We allow "recursive" symbolic refs. Only within reason, though */
#define MAXDEPTH 5

static int pushing;
static int aborted;
static signed char remote_dir_exists[256];

static struct curl_slist *no_pragma_header;

static int push_verbosely;
static int push_all = MATCH_REFS_NONE;
static int force_all;
static int dry_run;

static struct object_list *objects;

struct repo
{
	char *url;
	int path_len;
	int has_info_refs;
	int can_update_info_refs;
	int has_info_packs;
	struct packed_git *packs;
	struct remote_lock *locks;
};

static struct repo *remote;

enum transfer_state {
	NEED_FETCH,
	RUN_FETCH_LOOSE,
	RUN_FETCH_PACKED,
	NEED_PUSH,
	RUN_MKCOL,
	RUN_PUT,
	RUN_MOVE,
	ABORTED,
	COMPLETE,
};

struct transfer_request
{
	struct object *obj;
	char *url;
	char *dest;
	struct remote_lock *lock;
	struct curl_slist *headers;
	struct buffer buffer;
	char filename[PATH_MAX];
	char tmpfile[PATH_MAX];
	int local_fileno;
	FILE *local_stream;
	enum transfer_state state;
	CURLcode curl_result;
	char errorstr[CURL_ERROR_SIZE];
	long http_code;
	unsigned char real_sha1[20];
	SHA_CTX c;
	z_stream stream;
	int zret;
	int rename;
	void *userData;
	struct active_request_slot *slot;
	struct transfer_request *next;
};

static struct transfer_request *request_queue_head;

struct xml_ctx
{
	char *name;
	int len;
	char *cdata;
	void (*userFunc)(struct xml_ctx *ctx, int tag_closed);
	void *userData;
};

struct remote_lock
{
	char *url;
	char *owner;
	char *token;
	time_t start_time;
	long timeout;
	int refreshing;
	struct remote_lock *next;
};

/* Flags that control remote_ls processing */
#define PROCESS_FILES (1u << 0)
#define PROCESS_DIRS  (1u << 1)
#define RECURSIVE     (1u << 2)

/* Flags that remote_ls passes to callback functions */
#define IS_DIR (1u << 0)

struct remote_ls_ctx
{
	char *path;
	void (*userFunc)(struct remote_ls_ctx *ls);
	void *userData;
	int flags;
	char *dentry_name;
	int dentry_flags;
	struct remote_ls_ctx *parent;
};

static void finish_request(struct transfer_request *request);
static void release_request(struct transfer_request *request);

static void process_response(void *callback_data)
{
	struct transfer_request *request =
		(struct transfer_request *)callback_data;

	finish_request(request);
}

#ifdef USE_CURL_MULTI
static size_t fwrite_sha1_file(void *ptr, size_t eltsize, size_t nmemb,
			       void *data)
{
	unsigned char expn[4096];
	size_t size = eltsize * nmemb;
	int posn = 0;
	struct transfer_request *request = (struct transfer_request *)data;
	do {
		ssize_t retval = xwrite(request->local_fileno,
				       (char *) ptr + posn, size - posn);
		if (retval < 0)
			return posn;
		posn += retval;
	} while (posn < size);

	request->stream.avail_in = size;
	request->stream.next_in = ptr;
	do {
		request->stream.next_out = expn;
		request->stream.avail_out = sizeof(expn);
		request->zret = inflate(&request->stream, Z_SYNC_FLUSH);
		SHA1_Update(&request->c, expn,
			    sizeof(expn) - request->stream.avail_out);
	} while (request->stream.avail_in && request->zret == Z_OK);
	data_received++;
	return size;
}

static void start_fetch_loose(struct transfer_request *request)
{
	char *hex = sha1_to_hex(request->obj->sha1);
	char *filename;
	char prevfile[PATH_MAX];
	char *url;
	char *posn;
	int prevlocal;
	unsigned char prev_buf[PREV_BUF_SIZE];
	ssize_t prev_read = 0;
	long prev_posn = 0;
	char range[RANGE_HEADER_SIZE];
	struct curl_slist *range_header = NULL;
	struct active_request_slot *slot;

	filename = sha1_file_name(request->obj->sha1);
	snprintf(request->filename, sizeof(request->filename), "%s", filename);
	snprintf(request->tmpfile, sizeof(request->tmpfile),
		 "%s.temp", filename);

	snprintf(prevfile, sizeof(prevfile), "%s.prev", request->filename);
	unlink(prevfile);
	rename(request->tmpfile, prevfile);
	unlink(request->tmpfile);

	if (request->local_fileno != -1)
		error("fd leakage in start: %d", request->local_fileno);
	request->local_fileno = open(request->tmpfile,
				     O_WRONLY | O_CREAT | O_EXCL, 0666);
	/* This could have failed due to the "lazy directory creation";
	 * try to mkdir the last path component.
	 */
	if (request->local_fileno < 0 && errno == ENOENT) {
		char *dir = strrchr(request->tmpfile, '/');
		if (dir) {
			*dir = 0;
			mkdir(request->tmpfile, 0777);
			*dir = '/';
		}
		request->local_fileno = open(request->tmpfile,
					     O_WRONLY | O_CREAT | O_EXCL, 0666);
	}

	if (request->local_fileno < 0) {
		request->state = ABORTED;
		error("Couldn't create temporary file %s for %s: %s",
		      request->tmpfile, request->filename, strerror(errno));
		return;
	}

	memset(&request->stream, 0, sizeof(request->stream));

	inflateInit(&request->stream);

	SHA1_Init(&request->c);

	url = xmalloc(strlen(remote->url) + 50);
	request->url = xmalloc(strlen(remote->url) + 50);
	strcpy(url, remote->url);
	posn = url + strlen(remote->url);
	strcpy(posn, "objects/");
	posn += 8;
	memcpy(posn, hex, 2);
	posn += 2;
	*(posn++) = '/';
	strcpy(posn, hex + 2);
	strcpy(request->url, url);

	/* If a previous temp file is present, process what was already
	   fetched. */
	prevlocal = open(prevfile, O_RDONLY);
	if (prevlocal != -1) {
		do {
			prev_read = xread(prevlocal, prev_buf, PREV_BUF_SIZE);
			if (prev_read>0) {
				if (fwrite_sha1_file(prev_buf,
						     1,
						     prev_read,
						     request) == prev_read) {
					prev_posn += prev_read;
				} else {
					prev_read = -1;
				}
			}
		} while (prev_read > 0);
		close(prevlocal);
	}
	unlink(prevfile);

	/* Reset inflate/SHA1 if there was an error reading the previous temp
	   file; also rewind to the beginning of the local file. */
	if (prev_read == -1) {
		memset(&request->stream, 0, sizeof(request->stream));
		inflateInit(&request->stream);
		SHA1_Init(&request->c);
		if (prev_posn>0) {
			prev_posn = 0;
			lseek(request->local_fileno, 0, SEEK_SET);
			ftruncate(request->local_fileno, 0);
		}
	}

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	request->slot = slot;

	curl_easy_setopt(slot->curl, CURLOPT_FILE, request);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_sha1_file);
	curl_easy_setopt(slot->curl, CURLOPT_ERRORBUFFER, request->errorstr);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, no_pragma_header);

	/* If we have successfully processed data from a previous fetch
	   attempt, only fetch the data we don't already have. */
	if (prev_posn>0) {
		if (push_verbosely)
			fprintf(stderr,
				"Resuming fetch of object %s at byte %ld\n",
				hex, prev_posn);
		sprintf(range, "Range: bytes=%ld-", prev_posn);
		range_header = curl_slist_append(range_header, range);
		curl_easy_setopt(slot->curl,
				 CURLOPT_HTTPHEADER, range_header);
	}

	/* Try to get the request started, abort the request on error */
	request->state = RUN_FETCH_LOOSE;
	if (!start_active_slot(slot)) {
		fprintf(stderr, "Unable to start GET request\n");
		remote->can_update_info_refs = 0;
		release_request(request);
	}
}

static void start_mkcol(struct transfer_request *request)
{
	char *hex = sha1_to_hex(request->obj->sha1);
	struct active_request_slot *slot;
	char *posn;

	request->url = xmalloc(strlen(remote->url) + 13);
	strcpy(request->url, remote->url);
	posn = request->url + strlen(remote->url);
	strcpy(posn, "objects/");
	posn += 8;
	memcpy(posn, hex, 2);
	posn += 2;
	strcpy(posn, "/");

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1); /* undo PUT setup */
	curl_easy_setopt(slot->curl, CURLOPT_URL, request->url);
	curl_easy_setopt(slot->curl, CURLOPT_ERRORBUFFER, request->errorstr);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_MKCOL);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);

	if (start_active_slot(slot)) {
		request->slot = slot;
		request->state = RUN_MKCOL;
	} else {
		request->state = ABORTED;
		free(request->url);
		request->url = NULL;
	}
}
#endif

static void start_fetch_packed(struct transfer_request *request)
{
	char *url;
	struct packed_git *target;
	FILE *packfile;
	char *filename;
	long prev_posn = 0;
	char range[RANGE_HEADER_SIZE];
	struct curl_slist *range_header = NULL;

	struct transfer_request *check_request = request_queue_head;
	struct active_request_slot *slot;

	target = find_sha1_pack(request->obj->sha1, remote->packs);
	if (!target) {
		fprintf(stderr, "Unable to fetch %s, will not be able to update server info refs\n", sha1_to_hex(request->obj->sha1));
		remote->can_update_info_refs = 0;
		release_request(request);
		return;
	}

	fprintf(stderr,	"Fetching pack %s\n", sha1_to_hex(target->sha1));
	fprintf(stderr, " which contains %s\n", sha1_to_hex(request->obj->sha1));

	filename = sha1_pack_name(target->sha1);
	snprintf(request->filename, sizeof(request->filename), "%s", filename);
	snprintf(request->tmpfile, sizeof(request->tmpfile),
		 "%s.temp", filename);

	url = xmalloc(strlen(remote->url) + 64);
	sprintf(url, "%sobjects/pack/pack-%s.pack",
		remote->url, sha1_to_hex(target->sha1));

	/* Make sure there isn't another open request for this pack */
	while (check_request) {
		if (check_request->state == RUN_FETCH_PACKED &&
		    !strcmp(check_request->url, url)) {
			free(url);
			release_request(request);
			return;
		}
		check_request = check_request->next;
	}

	packfile = fopen(request->tmpfile, "a");
	if (!packfile) {
		fprintf(stderr, "Unable to open local file %s for pack",
			request->tmpfile);
		remote->can_update_info_refs = 0;
		free(url);
		return;
	}

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	request->slot = slot;
	request->local_stream = packfile;
	request->userData = target;

	request->url = url;
	curl_easy_setopt(slot->curl, CURLOPT_FILE, packfile);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, no_pragma_header);
	slot->local = packfile;

	/* If there is data present from a previous transfer attempt,
	   resume where it left off */
	prev_posn = ftell(packfile);
	if (prev_posn>0) {
		if (push_verbosely)
			fprintf(stderr,
				"Resuming fetch of pack %s at byte %ld\n",
				sha1_to_hex(target->sha1), prev_posn);
		sprintf(range, "Range: bytes=%ld-", prev_posn);
		range_header = curl_slist_append(range_header, range);
		curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, range_header);
	}

	/* Try to get the request started, abort the request on error */
	request->state = RUN_FETCH_PACKED;
	if (!start_active_slot(slot)) {
		fprintf(stderr, "Unable to start GET request\n");
		remote->can_update_info_refs = 0;
		release_request(request);
	}
}

static void start_put(struct transfer_request *request)
{
	char *hex = sha1_to_hex(request->obj->sha1);
	struct active_request_slot *slot;
	char *posn;
	enum object_type type;
	char hdr[50];
	void *unpacked;
	unsigned long len;
	int hdrlen;
	ssize_t size;
	z_stream stream;

	unpacked = read_sha1_file(request->obj->sha1, &type, &len);
	hdrlen = sprintf(hdr, "%s %lu", typename(type), len) + 1;

	/* Set it up */
	memset(&stream, 0, sizeof(stream));
	deflateInit(&stream, zlib_compression_level);
	size = deflateBound(&stream, len + hdrlen);
	strbuf_init(&request->buffer.buf, size);
	request->buffer.posn = 0;

	/* Compress it */
	stream.next_out = (unsigned char *)request->buffer.buf.buf;
	stream.avail_out = size;

	/* First header.. */
	stream.next_in = (void *)hdr;
	stream.avail_in = hdrlen;
	while (deflate(&stream, 0) == Z_OK)
		/* nothing */;

	/* Then the data itself.. */
	stream.next_in = unpacked;
	stream.avail_in = len;
	while (deflate(&stream, Z_FINISH) == Z_OK)
		/* nothing */;
	deflateEnd(&stream);
	free(unpacked);

	request->buffer.buf.len = stream.total_out;

	request->url = xmalloc(strlen(remote->url) +
			       strlen(request->lock->token) + 51);
	strcpy(request->url, remote->url);
	posn = request->url + strlen(remote->url);
	strcpy(posn, "objects/");
	posn += 8;
	memcpy(posn, hex, 2);
	posn += 2;
	*(posn++) = '/';
	strcpy(posn, hex + 2);
	request->dest = xmalloc(strlen(request->url) + 14);
	sprintf(request->dest, "Destination: %s", request->url);
	posn += 38;
	*(posn++) = '_';
	strcpy(posn, request->lock->token);

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	curl_easy_setopt(slot->curl, CURLOPT_INFILE, &request->buffer);
	curl_easy_setopt(slot->curl, CURLOPT_INFILESIZE, request->buffer.buf.len);
	curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, fread_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_PUT);
	curl_easy_setopt(slot->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(slot->curl, CURLOPT_PUT, 1);
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);
	curl_easy_setopt(slot->curl, CURLOPT_URL, request->url);

	if (start_active_slot(slot)) {
		request->slot = slot;
		request->state = RUN_PUT;
	} else {
		request->state = ABORTED;
		free(request->url);
		request->url = NULL;
	}
}

static void start_move(struct transfer_request *request)
{
	struct active_request_slot *slot;
	struct curl_slist *dav_headers = NULL;

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1); /* undo PUT setup */
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_MOVE);
	dav_headers = curl_slist_append(dav_headers, request->dest);
	dav_headers = curl_slist_append(dav_headers, "Overwrite: T");
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
	curl_easy_setopt(slot->curl, CURLOPT_URL, request->url);

	if (start_active_slot(slot)) {
		request->slot = slot;
		request->state = RUN_MOVE;
	} else {
		request->state = ABORTED;
		free(request->url);
		request->url = NULL;
	}
}

static int refresh_lock(struct remote_lock *lock)
{
	struct active_request_slot *slot;
	struct slot_results results;
	char *if_header;
	char timeout_header[25];
	struct curl_slist *dav_headers = NULL;
	int rc = 0;

	lock->refreshing = 1;

	if_header = xmalloc(strlen(lock->token) + 25);
	sprintf(if_header, "If: (<opaquelocktoken:%s>)", lock->token);
	sprintf(timeout_header, "Timeout: Second-%ld", lock->timeout);
	dav_headers = curl_slist_append(dav_headers, if_header);
	dav_headers = curl_slist_append(dav_headers, timeout_header);

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
	curl_easy_setopt(slot->curl, CURLOPT_URL, lock->url);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_LOCK);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result != CURLE_OK) {
			fprintf(stderr, "LOCK HTTP error %ld\n",
				results.http_code);
		} else {
			lock->start_time = time(NULL);
			rc = 1;
		}
	}

	lock->refreshing = 0;
	curl_slist_free_all(dav_headers);
	free(if_header);

	return rc;
}

static void check_locks(void)
{
	struct remote_lock *lock = remote->locks;
	time_t current_time = time(NULL);
	int time_remaining;

	while (lock) {
		time_remaining = lock->start_time + lock->timeout -
			current_time;
		if (!lock->refreshing && time_remaining < LOCK_REFRESH) {
			if (!refresh_lock(lock)) {
				fprintf(stderr,
					"Unable to refresh lock for %s\n",
					lock->url);
				aborted = 1;
				return;
			}
		}
		lock = lock->next;
	}
}

static void release_request(struct transfer_request *request)
{
	struct transfer_request *entry = request_queue_head;

	if (request == request_queue_head) {
		request_queue_head = request->next;
	} else {
		while (entry->next != NULL && entry->next != request)
			entry = entry->next;
		if (entry->next == request)
			entry->next = entry->next->next;
	}

	if (request->local_fileno != -1)
		close(request->local_fileno);
	if (request->local_stream)
		fclose(request->local_stream);
	free(request->url);
	free(request);
}

static void finish_request(struct transfer_request *request)
{
	struct stat st;
	struct packed_git *target;
	struct packed_git **lst;

	request->curl_result = request->slot->curl_result;
	request->http_code = request->slot->http_code;
	request->slot = NULL;

	/* Keep locks active */
	check_locks();

	if (request->headers != NULL)
		curl_slist_free_all(request->headers);

	/* URL is reused for MOVE after PUT */
	if (request->state != RUN_PUT) {
		free(request->url);
		request->url = NULL;
	}

	if (request->state == RUN_MKCOL) {
		if (request->curl_result == CURLE_OK ||
		    request->http_code == 405) {
			remote_dir_exists[request->obj->sha1[0]] = 1;
			start_put(request);
		} else {
			fprintf(stderr, "MKCOL %s failed, aborting (%d/%ld)\n",
				sha1_to_hex(request->obj->sha1),
				request->curl_result, request->http_code);
			request->state = ABORTED;
			aborted = 1;
		}
	} else if (request->state == RUN_PUT) {
		if (request->curl_result == CURLE_OK) {
			start_move(request);
		} else {
			fprintf(stderr,	"PUT %s failed, aborting (%d/%ld)\n",
				sha1_to_hex(request->obj->sha1),
				request->curl_result, request->http_code);
			request->state = ABORTED;
			aborted = 1;
		}
	} else if (request->state == RUN_MOVE) {
		if (request->curl_result == CURLE_OK) {
			if (push_verbosely)
				fprintf(stderr, "    sent %s\n",
					sha1_to_hex(request->obj->sha1));
			request->obj->flags |= REMOTE;
			release_request(request);
		} else {
			fprintf(stderr, "MOVE %s failed, aborting (%d/%ld)\n",
				sha1_to_hex(request->obj->sha1),
				request->curl_result, request->http_code);
			request->state = ABORTED;
			aborted = 1;
		}
	} else if (request->state == RUN_FETCH_LOOSE) {
		fchmod(request->local_fileno, 0444);
		close(request->local_fileno); request->local_fileno = -1;

		if (request->curl_result != CURLE_OK &&
		    request->http_code != 416) {
			if (stat(request->tmpfile, &st) == 0) {
				if (st.st_size == 0)
					unlink(request->tmpfile);
			}
		} else {
			if (request->http_code == 416)
				fprintf(stderr, "Warning: requested range invalid; we may already have all the data.\n");

			inflateEnd(&request->stream);
			SHA1_Final(request->real_sha1, &request->c);
			if (request->zret != Z_STREAM_END) {
				unlink(request->tmpfile);
			} else if (hashcmp(request->obj->sha1, request->real_sha1)) {
				unlink(request->tmpfile);
			} else {
				request->rename =
					move_temp_to_file(
						request->tmpfile,
						request->filename);
				if (request->rename == 0) {
					request->obj->flags |= (LOCAL | REMOTE);
				}
			}
		}

		/* Try fetching packed if necessary */
		if (request->obj->flags & LOCAL)
			release_request(request);
		else
			start_fetch_packed(request);

	} else if (request->state == RUN_FETCH_PACKED) {
		if (request->curl_result != CURLE_OK) {
			fprintf(stderr, "Unable to get pack file %s\n%s",
				request->url, curl_errorstr);
			remote->can_update_info_refs = 0;
		} else {
			off_t pack_size = ftell(request->local_stream);

			fclose(request->local_stream);
			request->local_stream = NULL;
			if (!move_temp_to_file(request->tmpfile,
					       request->filename)) {
				target = (struct packed_git *)request->userData;
				target->pack_size = pack_size;
				lst = &remote->packs;
				while (*lst != target)
					lst = &((*lst)->next);
				*lst = (*lst)->next;

				if (!verify_pack(target))
					install_packed_git(target);
				else
					remote->can_update_info_refs = 0;
			}
		}
		release_request(request);
	}
}

#ifdef USE_CURL_MULTI
static int fill_active_slot(void *unused)
{
	struct transfer_request *request = request_queue_head;

	if (aborted)
		return 0;

	for (request = request_queue_head; request; request = request->next) {
		if (request->state == NEED_FETCH) {
			start_fetch_loose(request);
			return 1;
		} else if (pushing && request->state == NEED_PUSH) {
			if (remote_dir_exists[request->obj->sha1[0]] == 1) {
				start_put(request);
			} else {
				start_mkcol(request);
			}
			return 1;
		}
	}
	return 0;
}
#endif

static void get_remote_object_list(unsigned char parent);

static void add_fetch_request(struct object *obj)
{
	struct transfer_request *request;

	check_locks();

	/*
	 * Don't fetch the object if it's known to exist locally
	 * or is already in the request queue
	 */
	if (remote_dir_exists[obj->sha1[0]] == -1)
		get_remote_object_list(obj->sha1[0]);
	if (obj->flags & (LOCAL | FETCHING))
		return;

	obj->flags |= FETCHING;
	request = xmalloc(sizeof(*request));
	request->obj = obj;
	request->url = NULL;
	request->lock = NULL;
	request->headers = NULL;
	request->local_fileno = -1;
	request->local_stream = NULL;
	request->state = NEED_FETCH;
	request->next = request_queue_head;
	request_queue_head = request;

#ifdef USE_CURL_MULTI
	fill_active_slots();
	step_active_slots();
#endif
}

static int add_send_request(struct object *obj, struct remote_lock *lock)
{
	struct transfer_request *request = request_queue_head;
	struct packed_git *target;

	/* Keep locks active */
	check_locks();

	/*
	 * Don't push the object if it's known to exist on the remote
	 * or is already in the request queue
	 */
	if (remote_dir_exists[obj->sha1[0]] == -1)
		get_remote_object_list(obj->sha1[0]);
	if (obj->flags & (REMOTE | PUSHING))
		return 0;
	target = find_sha1_pack(obj->sha1, remote->packs);
	if (target) {
		obj->flags |= REMOTE;
		return 0;
	}

	obj->flags |= PUSHING;
	request = xmalloc(sizeof(*request));
	request->obj = obj;
	request->url = NULL;
	request->lock = lock;
	request->headers = NULL;
	request->local_fileno = -1;
	request->local_stream = NULL;
	request->state = NEED_PUSH;
	request->next = request_queue_head;
	request_queue_head = request;

#ifdef USE_CURL_MULTI
	fill_active_slots();
	step_active_slots();
#endif

	return 1;
}

static int fetch_index(unsigned char *sha1)
{
	char *hex = sha1_to_hex(sha1);
	char *filename;
	char *url;
	char tmpfile[PATH_MAX];
	long prev_posn = 0;
	char range[RANGE_HEADER_SIZE];
	struct curl_slist *range_header = NULL;

	FILE *indexfile;
	struct active_request_slot *slot;
	struct slot_results results;

	/* Don't use the index if the pack isn't there */
	url = xmalloc(strlen(remote->url) + 64);
	sprintf(url, "%sobjects/pack/pack-%s.pack", remote->url, hex);
	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 1);
	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result != CURLE_OK) {
			free(url);
			return error("Unable to verify pack %s is available",
				     hex);
		}
	} else {
		free(url);
		return error("Unable to start request");
	}

	if (has_pack_index(sha1)) {
		free(url);
		return 0;
	}

	if (push_verbosely)
		fprintf(stderr, "Getting index for pack %s\n", hex);

	sprintf(url, "%sobjects/pack/pack-%s.idx", remote->url, hex);

	filename = sha1_pack_index_name(sha1);
	snprintf(tmpfile, sizeof(tmpfile), "%s.temp", filename);
	indexfile = fopen(tmpfile, "a");
	if (!indexfile) {
		free(url);
		return error("Unable to open local file %s for pack index",
			     tmpfile);
	}

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(slot->curl, CURLOPT_FILE, indexfile);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, no_pragma_header);
	slot->local = indexfile;

	/* If there is data present from a previous transfer attempt,
	   resume where it left off */
	prev_posn = ftell(indexfile);
	if (prev_posn>0) {
		if (push_verbosely)
			fprintf(stderr,
				"Resuming fetch of index for pack %s at byte %ld\n",
				hex, prev_posn);
		sprintf(range, "Range: bytes=%ld-", prev_posn);
		range_header = curl_slist_append(range_header, range);
		curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, range_header);
	}

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result != CURLE_OK) {
			free(url);
			fclose(indexfile);
			return error("Unable to get pack index %s\n%s", url,
				     curl_errorstr);
		}
	} else {
		free(url);
		fclose(indexfile);
		return error("Unable to start request");
	}

	free(url);
	fclose(indexfile);

	return move_temp_to_file(tmpfile, filename);
}

static int setup_index(unsigned char *sha1)
{
	struct packed_git *new_pack;

	if (fetch_index(sha1))
		return -1;

	new_pack = parse_pack_index(sha1);
	new_pack->next = remote->packs;
	remote->packs = new_pack;
	return 0;
}

static int fetch_indices(void)
{
	unsigned char sha1[20];
	char *url;
	struct strbuf buffer = STRBUF_INIT;
	char *data;
	int i = 0;

	struct active_request_slot *slot;
	struct slot_results results;

	if (push_verbosely)
		fprintf(stderr, "Getting pack list\n");

	url = xmalloc(strlen(remote->url) + 20);
	sprintf(url, "%sobjects/info/packs", remote->url);

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &buffer);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, NULL);
	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result != CURLE_OK) {
			strbuf_release(&buffer);
			free(url);
			if (results.http_code == 404)
				return 0;
			else
				return error("%s", curl_errorstr);
		}
	} else {
		strbuf_release(&buffer);
		free(url);
		return error("Unable to start request");
	}
	free(url);

	data = buffer.buf;
	while (i < buffer.len) {
		switch (data[i]) {
		case 'P':
			i++;
			if (i + 52 < buffer.len &&
			    !prefixcmp(data + i, " pack-") &&
			    !prefixcmp(data + i + 46, ".pack\n")) {
				get_sha1_hex(data + i + 6, sha1);
				setup_index(sha1);
				i += 51;
				break;
			}
		default:
			while (data[i] != '\n')
				i++;
		}
		i++;
	}

	strbuf_release(&buffer);
	return 0;
}

static void one_remote_object(const char *hex)
{
	unsigned char sha1[20];
	struct object *obj;

	if (get_sha1_hex(hex, sha1) != 0)
		return;

	obj = lookup_object(sha1);
	if (!obj)
		obj = parse_object(sha1);

	/* Ignore remote objects that don't exist locally */
	if (!obj)
		return;

	obj->flags |= REMOTE;
	if (!object_list_contains(objects, obj))
		object_list_insert(obj, &objects);
}

static void handle_lockprop_ctx(struct xml_ctx *ctx, int tag_closed)
{
	int *lock_flags = (int *)ctx->userData;

	if (tag_closed) {
		if (!strcmp(ctx->name, DAV_CTX_LOCKENTRY)) {
			if ((*lock_flags & DAV_PROP_LOCKEX) &&
			    (*lock_flags & DAV_PROP_LOCKWR)) {
				*lock_flags |= DAV_LOCK_OK;
			}
			*lock_flags &= DAV_LOCK_OK;
		} else if (!strcmp(ctx->name, DAV_CTX_LOCKTYPE_WRITE)) {
			*lock_flags |= DAV_PROP_LOCKWR;
		} else if (!strcmp(ctx->name, DAV_CTX_LOCKTYPE_EXCLUSIVE)) {
			*lock_flags |= DAV_PROP_LOCKEX;
		}
	}
}

static void handle_new_lock_ctx(struct xml_ctx *ctx, int tag_closed)
{
	struct remote_lock *lock = (struct remote_lock *)ctx->userData;

	if (tag_closed && ctx->cdata) {
		if (!strcmp(ctx->name, DAV_ACTIVELOCK_OWNER)) {
			lock->owner = xmalloc(strlen(ctx->cdata) + 1);
			strcpy(lock->owner, ctx->cdata);
		} else if (!strcmp(ctx->name, DAV_ACTIVELOCK_TIMEOUT)) {
			if (!prefixcmp(ctx->cdata, "Second-"))
				lock->timeout =
					strtol(ctx->cdata + 7, NULL, 10);
		} else if (!strcmp(ctx->name, DAV_ACTIVELOCK_TOKEN)) {
			if (!prefixcmp(ctx->cdata, "opaquelocktoken:")) {
				lock->token = xmalloc(strlen(ctx->cdata) - 15);
				strcpy(lock->token, ctx->cdata + 16);
			}
		}
	}
}

static void one_remote_ref(char *refname);

static void
xml_start_tag(void *userData, const char *name, const char **atts)
{
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
	const char *c = strchr(name, ':');
	int new_len;

	if (c == NULL)
		c = name;
	else
		c++;

	new_len = strlen(ctx->name) + strlen(c) + 2;

	if (new_len > ctx->len) {
		ctx->name = xrealloc(ctx->name, new_len);
		ctx->len = new_len;
	}
	strcat(ctx->name, ".");
	strcat(ctx->name, c);

	free(ctx->cdata);
	ctx->cdata = NULL;

	ctx->userFunc(ctx, 0);
}

static void
xml_end_tag(void *userData, const char *name)
{
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
	const char *c = strchr(name, ':');
	char *ep;

	ctx->userFunc(ctx, 1);

	if (c == NULL)
		c = name;
	else
		c++;

	ep = ctx->name + strlen(ctx->name) - strlen(c) - 1;
	*ep = 0;
}

static void
xml_cdata(void *userData, const XML_Char *s, int len)
{
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
	free(ctx->cdata);
	ctx->cdata = xmemdupz(s, len);
}

static struct remote_lock *lock_remote(const char *path, long timeout)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct strbuf in_buffer = STRBUF_INIT;
	char *url;
	char *ep;
	char timeout_header[25];
	struct remote_lock *lock = NULL;
	struct curl_slist *dav_headers = NULL;
	struct xml_ctx ctx;

	url = xmalloc(strlen(remote->url) + strlen(path) + 1);
	sprintf(url, "%s%s", remote->url, path);

	/* Make sure leading directories exist for the remote ref */
	ep = strchr(url + strlen(remote->url) + 1, '/');
	while (ep) {
		*ep = 0;
		slot = get_active_slot();
		slot->results = &results;
		curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);
		curl_easy_setopt(slot->curl, CURLOPT_URL, url);
		curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_MKCOL);
		curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
		if (start_active_slot(slot)) {
			run_active_slot(slot);
			if (results.curl_result != CURLE_OK &&
			    results.http_code != 405) {
				fprintf(stderr,
					"Unable to create branch path %s\n",
					url);
				free(url);
				return NULL;
			}
		} else {
			fprintf(stderr, "Unable to start MKCOL request\n");
			free(url);
			return NULL;
		}
		*ep = '/';
		ep = strchr(ep + 1, '/');
	}

	strbuf_addf(&out_buffer.buf, LOCK_REQUEST, git_default_email);

	sprintf(timeout_header, "Timeout: Second-%ld", timeout);
	dav_headers = curl_slist_append(dav_headers, timeout_header);
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_INFILE, &out_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_INFILESIZE, out_buffer.buf.len);
	curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, fread_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &in_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_LOCK);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	lock = xcalloc(1, sizeof(*lock));
	lock->timeout = -1;

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK) {
			XML_Parser parser = XML_ParserCreate(NULL);
			enum XML_Status result;
			ctx.name = xcalloc(10, 1);
			ctx.len = 0;
			ctx.cdata = NULL;
			ctx.userFunc = handle_new_lock_ctx;
			ctx.userData = lock;
			XML_SetUserData(parser, &ctx);
			XML_SetElementHandler(parser, xml_start_tag,
					      xml_end_tag);
			XML_SetCharacterDataHandler(parser, xml_cdata);
			result = XML_Parse(parser, in_buffer.buf,
					   in_buffer.len, 1);
			free(ctx.name);
			if (result != XML_STATUS_OK) {
				fprintf(stderr, "XML error: %s\n",
					XML_ErrorString(
						XML_GetErrorCode(parser)));
				lock->timeout = -1;
			}
			XML_ParserFree(parser);
		}
	} else {
		fprintf(stderr, "Unable to start LOCK request\n");
	}

	curl_slist_free_all(dav_headers);
	strbuf_release(&out_buffer.buf);
	strbuf_release(&in_buffer);

	if (lock->token == NULL || lock->timeout <= 0) {
		free(lock->token);
		free(lock->owner);
		free(url);
		free(lock);
		lock = NULL;
	} else {
		lock->url = url;
		lock->start_time = time(NULL);
		lock->next = remote->locks;
		remote->locks = lock;
	}

	return lock;
}

static int unlock_remote(struct remote_lock *lock)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct remote_lock *prev = remote->locks;
	char *lock_token_header;
	struct curl_slist *dav_headers = NULL;
	int rc = 0;

	lock_token_header = xmalloc(strlen(lock->token) + 31);
	sprintf(lock_token_header, "Lock-Token: <opaquelocktoken:%s>",
		lock->token);
	dav_headers = curl_slist_append(dav_headers, lock_token_header);

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
	curl_easy_setopt(slot->curl, CURLOPT_URL, lock->url);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_UNLOCK);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK)
			rc = 1;
		else
			fprintf(stderr, "UNLOCK HTTP error %ld\n",
				results.http_code);
	} else {
		fprintf(stderr, "Unable to start UNLOCK request\n");
	}

	curl_slist_free_all(dav_headers);
	free(lock_token_header);

	if (remote->locks == lock) {
		remote->locks = lock->next;
	} else {
		while (prev && prev->next != lock)
			prev = prev->next;
		if (prev)
			prev->next = prev->next->next;
	}

	free(lock->owner);
	free(lock->url);
	free(lock->token);
	free(lock);

	return rc;
}

static void remove_locks(void)
{
	struct remote_lock *lock = remote->locks;

	fprintf(stderr, "Removing remote locks...\n");
	while (lock) {
		unlock_remote(lock);
		lock = lock->next;
	}
}

static void remove_locks_on_signal(int signo)
{
	remove_locks();
	signal(signo, SIG_DFL);
	raise(signo);
}

static void remote_ls(const char *path, int flags,
		      void (*userFunc)(struct remote_ls_ctx *ls),
		      void *userData);

static void process_ls_object(struct remote_ls_ctx *ls)
{
	unsigned int *parent = (unsigned int *)ls->userData;
	char *path = ls->dentry_name;
	char *obj_hex;

	if (!strcmp(ls->path, ls->dentry_name) && (ls->flags & IS_DIR)) {
		remote_dir_exists[*parent] = 1;
		return;
	}

	if (strlen(path) != 49)
		return;
	path += 8;
	obj_hex = xmalloc(strlen(path));
	/* NB: path is not null-terminated, can not use strlcpy here */
	memcpy(obj_hex, path, 2);
	strcpy(obj_hex + 2, path + 3);
	one_remote_object(obj_hex);
	free(obj_hex);
}

static void process_ls_ref(struct remote_ls_ctx *ls)
{
	if (!strcmp(ls->path, ls->dentry_name) && (ls->dentry_flags & IS_DIR)) {
		fprintf(stderr, "  %s\n", ls->dentry_name);
		return;
	}

	if (!(ls->dentry_flags & IS_DIR))
		one_remote_ref(ls->dentry_name);
}

static void handle_remote_ls_ctx(struct xml_ctx *ctx, int tag_closed)
{
	struct remote_ls_ctx *ls = (struct remote_ls_ctx *)ctx->userData;

	if (tag_closed) {
		if (!strcmp(ctx->name, DAV_PROPFIND_RESP) && ls->dentry_name) {
			if (ls->dentry_flags & IS_DIR) {
				if (ls->flags & PROCESS_DIRS) {
					ls->userFunc(ls);
				}
				if (strcmp(ls->dentry_name, ls->path) &&
				    ls->flags & RECURSIVE) {
					remote_ls(ls->dentry_name,
						  ls->flags,
						  ls->userFunc,
						  ls->userData);
				}
			} else if (ls->flags & PROCESS_FILES) {
				ls->userFunc(ls);
			}
		} else if (!strcmp(ctx->name, DAV_PROPFIND_NAME) && ctx->cdata) {
			ls->dentry_name = xmalloc(strlen(ctx->cdata) -
						  remote->path_len + 1);
			strcpy(ls->dentry_name, ctx->cdata + remote->path_len);
		} else if (!strcmp(ctx->name, DAV_PROPFIND_COLLECTION)) {
			ls->dentry_flags |= IS_DIR;
		}
	} else if (!strcmp(ctx->name, DAV_PROPFIND_RESP)) {
		free(ls->dentry_name);
		ls->dentry_name = NULL;
		ls->dentry_flags = 0;
	}
}

static void remote_ls(const char *path, int flags,
		      void (*userFunc)(struct remote_ls_ctx *ls),
		      void *userData)
{
	char *url = xmalloc(strlen(remote->url) + strlen(path) + 1);
	struct active_request_slot *slot;
	struct slot_results results;
	struct strbuf in_buffer = STRBUF_INIT;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct curl_slist *dav_headers = NULL;
	struct xml_ctx ctx;
	struct remote_ls_ctx ls;

	ls.flags = flags;
	ls.path = xstrdup(path);
	ls.dentry_name = NULL;
	ls.dentry_flags = 0;
	ls.userData = userData;
	ls.userFunc = userFunc;

	sprintf(url, "%s%s", remote->url, path);

	strbuf_addf(&out_buffer.buf, PROPFIND_ALL_REQUEST);

	dav_headers = curl_slist_append(dav_headers, "Depth: 1");
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_INFILE, &out_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_INFILESIZE, out_buffer.buf.len);
	curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, fread_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &in_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_PROPFIND);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK) {
			XML_Parser parser = XML_ParserCreate(NULL);
			enum XML_Status result;
			ctx.name = xcalloc(10, 1);
			ctx.len = 0;
			ctx.cdata = NULL;
			ctx.userFunc = handle_remote_ls_ctx;
			ctx.userData = &ls;
			XML_SetUserData(parser, &ctx);
			XML_SetElementHandler(parser, xml_start_tag,
					      xml_end_tag);
			XML_SetCharacterDataHandler(parser, xml_cdata);
			result = XML_Parse(parser, in_buffer.buf,
					   in_buffer.len, 1);
			free(ctx.name);

			if (result != XML_STATUS_OK) {
				fprintf(stderr, "XML error: %s\n",
					XML_ErrorString(
						XML_GetErrorCode(parser)));
			}
			XML_ParserFree(parser);
		}
	} else {
		fprintf(stderr, "Unable to start PROPFIND request\n");
	}

	free(ls.path);
	free(url);
	strbuf_release(&out_buffer.buf);
	strbuf_release(&in_buffer);
	curl_slist_free_all(dav_headers);
}

static void get_remote_object_list(unsigned char parent)
{
	char path[] = "objects/XX/";
	static const char hex[] = "0123456789abcdef";
	unsigned int val = parent;

	path[8] = hex[val >> 4];
	path[9] = hex[val & 0xf];
	remote_dir_exists[val] = 0;
	remote_ls(path, (PROCESS_FILES | PROCESS_DIRS),
		  process_ls_object, &val);
}

static int locking_available(void)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct strbuf in_buffer = STRBUF_INIT;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct curl_slist *dav_headers = NULL;
	struct xml_ctx ctx;
	int lock_flags = 0;

	strbuf_addf(&out_buffer.buf, PROPFIND_SUPPORTEDLOCK_REQUEST, remote->url);

	dav_headers = curl_slist_append(dav_headers, "Depth: 0");
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_INFILE, &out_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_INFILESIZE, out_buffer.buf.len);
	curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, fread_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &in_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_URL, remote->url);
	curl_easy_setopt(slot->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_PROPFIND);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK) {
			XML_Parser parser = XML_ParserCreate(NULL);
			enum XML_Status result;
			ctx.name = xcalloc(10, 1);
			ctx.len = 0;
			ctx.cdata = NULL;
			ctx.userFunc = handle_lockprop_ctx;
			ctx.userData = &lock_flags;
			XML_SetUserData(parser, &ctx);
			XML_SetElementHandler(parser, xml_start_tag,
					      xml_end_tag);
			result = XML_Parse(parser, in_buffer.buf,
					   in_buffer.len, 1);
			free(ctx.name);

			if (result != XML_STATUS_OK) {
				fprintf(stderr, "XML error: %s\n",
					XML_ErrorString(
						XML_GetErrorCode(parser)));
				lock_flags = 0;
			}
			XML_ParserFree(parser);
			if (!lock_flags)
				error("Error: no DAV locking support on %s",
				      remote->url);

		} else {
			error("Cannot access URL %s, return code %d",
			      remote->url, results.curl_result);
			lock_flags = 0;
		}
	} else {
		error("Unable to start PROPFIND request on %s", remote->url);
	}

	strbuf_release(&out_buffer.buf);
	strbuf_release(&in_buffer);
	curl_slist_free_all(dav_headers);

	return lock_flags;
}

static struct object_list **add_one_object(struct object *obj, struct object_list **p)
{
	struct object_list *entry = xmalloc(sizeof(struct object_list));
	entry->item = obj;
	entry->next = *p;
	*p = entry;
	return &entry->next;
}

static struct object_list **process_blob(struct blob *blob,
					 struct object_list **p,
					 struct name_path *path,
					 const char *name)
{
	struct object *obj = &blob->object;

	obj->flags |= LOCAL;

	if (obj->flags & (UNINTERESTING | SEEN))
		return p;

	obj->flags |= SEEN;
	return add_one_object(obj, p);
}

static struct object_list **process_tree(struct tree *tree,
					 struct object_list **p,
					 struct name_path *path,
					 const char *name)
{
	struct object *obj = &tree->object;
	struct tree_desc desc;
	struct name_entry entry;
	struct name_path me;

	obj->flags |= LOCAL;

	if (obj->flags & (UNINTERESTING | SEEN))
		return p;
	if (parse_tree(tree) < 0)
		die("bad tree object %s", sha1_to_hex(obj->sha1));

	obj->flags |= SEEN;
	name = xstrdup(name);
	p = add_one_object(obj, p);
	me.up = path;
	me.elem = name;
	me.elem_len = strlen(name);

	init_tree_desc(&desc, tree->buffer, tree->size);

	while (tree_entry(&desc, &entry))
		switch (object_type(entry.mode)) {
		case OBJ_TREE:
			p = process_tree(lookup_tree(entry.sha1), p, &me, name);
			break;
		case OBJ_BLOB:
			p = process_blob(lookup_blob(entry.sha1), p, &me, name);
			break;
		default:
			/* Subproject commit - not in this repository */
			break;
		}

	free(tree->buffer);
	tree->buffer = NULL;
	return p;
}

static int get_delta(struct rev_info *revs, struct remote_lock *lock)
{
	int i;
	struct commit *commit;
	struct object_list **p = &objects;
	int count = 0;

	while ((commit = get_revision(revs)) != NULL) {
		p = process_tree(commit->tree, p, NULL, "");
		commit->object.flags |= LOCAL;
		if (!(commit->object.flags & UNINTERESTING))
			count += add_send_request(&commit->object, lock);
	}

	for (i = 0; i < revs->pending.nr; i++) {
		struct object_array_entry *entry = revs->pending.objects + i;
		struct object *obj = entry->item;
		const char *name = entry->name;

		if (obj->flags & (UNINTERESTING | SEEN))
			continue;
		if (obj->type == OBJ_TAG) {
			obj->flags |= SEEN;
			p = add_one_object(obj, p);
			continue;
		}
		if (obj->type == OBJ_TREE) {
			p = process_tree((struct tree *)obj, p, NULL, name);
			continue;
		}
		if (obj->type == OBJ_BLOB) {
			p = process_blob((struct blob *)obj, p, NULL, name);
			continue;
		}
		die("unknown pending object %s (%s)", sha1_to_hex(obj->sha1), name);
	}

	while (objects) {
		if (!(objects->item->flags & UNINTERESTING))
			count += add_send_request(objects->item, lock);
		objects = objects->next;
	}

	return count;
}

static int update_remote(unsigned char *sha1, struct remote_lock *lock)
{
	struct active_request_slot *slot;
	struct slot_results results;
	char *if_header;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct curl_slist *dav_headers = NULL;

	if_header = xmalloc(strlen(lock->token) + 25);
	sprintf(if_header, "If: (<opaquelocktoken:%s>)", lock->token);
	dav_headers = curl_slist_append(dav_headers, if_header);

	strbuf_addf(&out_buffer.buf, "%s\n", sha1_to_hex(sha1));

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_INFILE, &out_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_INFILESIZE, out_buffer.buf.len);
	curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, fread_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_PUT);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
	curl_easy_setopt(slot->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(slot->curl, CURLOPT_PUT, 1);
	curl_easy_setopt(slot->curl, CURLOPT_URL, lock->url);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		strbuf_release(&out_buffer.buf);
		free(if_header);
		if (results.curl_result != CURLE_OK) {
			fprintf(stderr,
				"PUT error: curl result=%d, HTTP code=%ld\n",
				results.curl_result, results.http_code);
			/* We should attempt recovery? */
			return 0;
		}
	} else {
		strbuf_release(&out_buffer.buf);
		free(if_header);
		fprintf(stderr, "Unable to start PUT request\n");
		return 0;
	}

	return 1;
}

static struct ref *local_refs, **local_tail;
static struct ref *remote_refs, **remote_tail;

static int one_local_ref(const char *refname, const unsigned char *sha1, int flag, void *cb_data)
{
	struct ref *ref;
	int len = strlen(refname) + 1;
	ref = xcalloc(1, sizeof(*ref) + len);
	hashcpy(ref->new_sha1, sha1);
	memcpy(ref->name, refname, len);
	*local_tail = ref;
	local_tail = &ref->next;
	return 0;
}

static void one_remote_ref(char *refname)
{
	struct ref *ref;
	struct object *obj;

	ref = alloc_ref_from_str(refname);

	if (http_fetch_ref(remote->url, ref) != 0) {
		fprintf(stderr,
			"Unable to fetch ref %s from %s\n",
			refname, remote->url);
		free(ref);
		return;
	}

	/*
	 * Fetch a copy of the object if it doesn't exist locally - it
	 * may be required for updating server info later.
	 */
	if (remote->can_update_info_refs && !has_sha1_file(ref->old_sha1)) {
		obj = lookup_unknown_object(ref->old_sha1);
		if (obj) {
			fprintf(stderr,	"  fetch %s for %s\n",
				sha1_to_hex(ref->old_sha1), refname);
			add_fetch_request(obj);
		}
	}

	*remote_tail = ref;
	remote_tail = &ref->next;
}

static void get_local_heads(void)
{
	local_tail = &local_refs;
	for_each_ref(one_local_ref, NULL);
}

static void get_dav_remote_heads(void)
{
	remote_tail = &remote_refs;
	remote_ls("refs/", (PROCESS_FILES | PROCESS_DIRS | RECURSIVE), process_ls_ref, NULL);
}

static int is_zero_sha1(const unsigned char *sha1)
{
	int i;

	for (i = 0; i < 20; i++) {
		if (*sha1++)
			return 0;
	}
	return 1;
}

static void unmark_and_free(struct commit_list *list, unsigned int mark)
{
	while (list) {
		struct commit_list *temp = list;
		temp->item->object.flags &= ~mark;
		list = temp->next;
		free(temp);
	}
}

static int ref_newer(const unsigned char *new_sha1,
		     const unsigned char *old_sha1)
{
	struct object *o;
	struct commit *old, *new;
	struct commit_list *list, *used;
	int found = 0;

	/* Both new and old must be commit-ish and new is descendant of
	 * old.  Otherwise we require --force.
	 */
	o = deref_tag(parse_object(old_sha1), NULL, 0);
	if (!o || o->type != OBJ_COMMIT)
		return 0;
	old = (struct commit *) o;

	o = deref_tag(parse_object(new_sha1), NULL, 0);
	if (!o || o->type != OBJ_COMMIT)
		return 0;
	new = (struct commit *) o;

	if (parse_commit(new) < 0)
		return 0;

	used = list = NULL;
	commit_list_insert(new, &list);
	while (list) {
		new = pop_most_recent_commit(&list, TMP_MARK);
		commit_list_insert(new, &used);
		if (new == old) {
			found = 1;
			break;
		}
	}
	unmark_and_free(list, TMP_MARK);
	unmark_and_free(used, TMP_MARK);
	return found;
}

static void add_remote_info_ref(struct remote_ls_ctx *ls)
{
	struct strbuf *buf = (struct strbuf *)ls->userData;
	struct object *o;
	int len;
	char *ref_info;
	struct ref *ref;

	ref = alloc_ref_from_str(ls->dentry_name);

	if (http_fetch_ref(remote->url, ref) != 0) {
		fprintf(stderr,
			"Unable to fetch ref %s from %s\n",
			ls->dentry_name, remote->url);
		aborted = 1;
		free(ref);
		return;
	}

	o = parse_object(ref->old_sha1);
	if (!o) {
		fprintf(stderr,
			"Unable to parse object %s for remote ref %s\n",
			sha1_to_hex(ref->old_sha1), ls->dentry_name);
		aborted = 1;
		free(ref);
		return;
	}

	len = strlen(ls->dentry_name) + 42;
	ref_info = xcalloc(len + 1, 1);
	sprintf(ref_info, "%s	%s\n",
		sha1_to_hex(ref->old_sha1), ls->dentry_name);
	fwrite_buffer(ref_info, 1, len, buf);
	free(ref_info);

	if (o->type == OBJ_TAG) {
		o = deref_tag(o, ls->dentry_name, 0);
		if (o) {
			len = strlen(ls->dentry_name) + 45;
			ref_info = xcalloc(len + 1, 1);
			sprintf(ref_info, "%s	%s^{}\n",
				sha1_to_hex(o->sha1), ls->dentry_name);
			fwrite_buffer(ref_info, 1, len, buf);
			free(ref_info);
		}
	}
	free(ref);
}

static void update_remote_info_refs(struct remote_lock *lock)
{
	struct buffer buffer = { STRBUF_INIT, 0 };
	struct active_request_slot *slot;
	struct slot_results results;
	char *if_header;
	struct curl_slist *dav_headers = NULL;

	remote_ls("refs/", (PROCESS_FILES | RECURSIVE),
		  add_remote_info_ref, &buffer.buf);
	if (!aborted) {
		if_header = xmalloc(strlen(lock->token) + 25);
		sprintf(if_header, "If: (<opaquelocktoken:%s>)", lock->token);
		dav_headers = curl_slist_append(dav_headers, if_header);

		slot = get_active_slot();
		slot->results = &results;
		curl_easy_setopt(slot->curl, CURLOPT_INFILE, &buffer);
		curl_easy_setopt(slot->curl, CURLOPT_INFILESIZE, buffer.buf.len);
		curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, fread_buffer);
		curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
		curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_PUT);
		curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
		curl_easy_setopt(slot->curl, CURLOPT_UPLOAD, 1);
		curl_easy_setopt(slot->curl, CURLOPT_PUT, 1);
		curl_easy_setopt(slot->curl, CURLOPT_URL, lock->url);

		if (start_active_slot(slot)) {
			run_active_slot(slot);
			if (results.curl_result != CURLE_OK) {
				fprintf(stderr,
					"PUT error: curl result=%d, HTTP code=%ld\n",
					results.curl_result, results.http_code);
			}
		}
		free(if_header);
	}
	strbuf_release(&buffer.buf);
}

static int remote_exists(const char *path)
{
	char *url = xmalloc(strlen(remote->url) + strlen(path) + 1);
	struct active_request_slot *slot;
	struct slot_results results;
	int ret = -1;

	sprintf(url, "%s%s", remote->url, path);

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 1);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.http_code == 404)
			ret = 0;
		else if (results.curl_result == CURLE_OK)
			ret = 1;
		else
			fprintf(stderr, "HEAD HTTP error %ld\n", results.http_code);
	} else {
		fprintf(stderr, "Unable to start HEAD request\n");
	}

	free(url);
	return ret;
}

static void fetch_symref(const char *path, char **symref, unsigned char *sha1)
{
	char *url;
	struct strbuf buffer = STRBUF_INIT;
	struct active_request_slot *slot;
	struct slot_results results;

	url = xmalloc(strlen(remote->url) + strlen(path) + 1);
	sprintf(url, "%s%s", remote->url, path);

	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &buffer);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, NULL);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result != CURLE_OK) {
			die("Couldn't get %s for remote symref\n%s",
			    url, curl_errorstr);
		}
	} else {
		die("Unable to start remote symref request");
	}
	free(url);

	free(*symref);
	*symref = NULL;
	hashclr(sha1);

	if (buffer.len == 0)
		return;

	/* If it's a symref, set the refname; otherwise try for a sha1 */
	if (!prefixcmp((char *)buffer.buf, "ref: ")) {
		*symref = xmemdupz((char *)buffer.buf + 5, buffer.len - 6);
	} else {
		get_sha1_hex(buffer.buf, sha1);
	}

	strbuf_release(&buffer);
}

static int verify_merge_base(unsigned char *head_sha1, unsigned char *branch_sha1)
{
	struct commit *head = lookup_commit(head_sha1);
	struct commit *branch = lookup_commit(branch_sha1);
	struct commit_list *merge_bases = get_merge_bases(head, branch, 1);

	return (merge_bases && !merge_bases->next && merge_bases->item == branch);
}

static int delete_remote_branch(char *pattern, int force)
{
	struct ref *refs = remote_refs;
	struct ref *remote_ref = NULL;
	unsigned char head_sha1[20];
	char *symref = NULL;
	int match;
	int patlen = strlen(pattern);
	int i;
	struct active_request_slot *slot;
	struct slot_results results;
	char *url;

	/* Find the remote branch(es) matching the specified branch name */
	for (match = 0; refs; refs = refs->next) {
		char *name = refs->name;
		int namelen = strlen(name);
		if (namelen < patlen ||
		    memcmp(name + namelen - patlen, pattern, patlen))
			continue;
		if (namelen != patlen && name[namelen - patlen - 1] != '/')
			continue;
		match++;
		remote_ref = refs;
	}
	if (match == 0)
		return error("No remote branch matches %s", pattern);
	if (match != 1)
		return error("More than one remote branch matches %s",
			     pattern);

	/*
	 * Remote HEAD must be a symref (not exactly foolproof; a remote
	 * symlink to a symref will look like a symref)
	 */
	fetch_symref("HEAD", &symref, head_sha1);
	if (!symref)
		return error("Remote HEAD is not a symref");

	/* Remote branch must not be the remote HEAD */
	for (i=0; symref && i<MAXDEPTH; i++) {
		if (!strcmp(remote_ref->name, symref))
			return error("Remote branch %s is the current HEAD",
				     remote_ref->name);
		fetch_symref(symref, &symref, head_sha1);
	}

	/* Run extra sanity checks if delete is not forced */
	if (!force) {
		/* Remote HEAD must resolve to a known object */
		if (symref)
			return error("Remote HEAD symrefs too deep");
		if (is_zero_sha1(head_sha1))
			return error("Unable to resolve remote HEAD");
		if (!has_sha1_file(head_sha1))
			return error("Remote HEAD resolves to object %s\nwhich does not exist locally, perhaps you need to fetch?", sha1_to_hex(head_sha1));

		/* Remote branch must resolve to a known object */
		if (is_zero_sha1(remote_ref->old_sha1))
			return error("Unable to resolve remote branch %s",
				     remote_ref->name);
		if (!has_sha1_file(remote_ref->old_sha1))
			return error("Remote branch %s resolves to object %s\nwhich does not exist locally, perhaps you need to fetch?", remote_ref->name, sha1_to_hex(remote_ref->old_sha1));

		/* Remote branch must be an ancestor of remote HEAD */
		if (!verify_merge_base(head_sha1, remote_ref->old_sha1)) {
			return error("The branch '%s' is not an ancestor "
				     "of your current HEAD.\n"
				     "If you are sure you want to delete it,"
				     " run:\n\t'git http-push -D %s %s'",
				     remote_ref->name, remote->url, pattern);
		}
	}

	/* Send delete request */
	fprintf(stderr, "Removing remote branch '%s'\n", remote_ref->name);
	if (dry_run)
		return 0;
	url = xmalloc(strlen(remote->url) + strlen(remote_ref->name) + 1);
	sprintf(url, "%s%s", remote->url, remote_ref->name);
	slot = get_active_slot();
	slot->results = &results;
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_null);
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, DAV_DELETE);
	if (start_active_slot(slot)) {
		run_active_slot(slot);
		free(url);
		if (results.curl_result != CURLE_OK)
			return error("DELETE request failed (%d/%ld)\n",
				     results.curl_result, results.http_code);
	} else {
		free(url);
		return error("Unable to start DELETE request");
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct transfer_request *request;
	struct transfer_request *next_request;
	int nr_refspec = 0;
	char **refspec = NULL;
	struct remote_lock *ref_lock = NULL;
	struct remote_lock *info_ref_lock = NULL;
	struct rev_info revs;
	int delete_branch = 0;
	int force_delete = 0;
	int objects_to_send;
	int rc = 0;
	int i;
	int new_refs;
	struct ref *ref;
	char *rewritten_url = NULL;

	setup_git_directory();

	remote = xcalloc(sizeof(*remote), 1);

	argv++;
	for (i = 1; i < argc; i++, argv++) {
		char *arg = *argv;

		if (*arg == '-') {
			if (!strcmp(arg, "--all")) {
				push_all = MATCH_REFS_ALL;
				continue;
			}
			if (!strcmp(arg, "--force")) {
				force_all = 1;
				continue;
			}
			if (!strcmp(arg, "--dry-run")) {
				dry_run = 1;
				continue;
			}
			if (!strcmp(arg, "--verbose")) {
				push_verbosely = 1;
				continue;
			}
			if (!strcmp(arg, "-d")) {
				delete_branch = 1;
				continue;
			}
			if (!strcmp(arg, "-D")) {
				delete_branch = 1;
				force_delete = 1;
				continue;
			}
		}
		if (!remote->url) {
			char *path = strstr(arg, "//");
			remote->url = arg;
			if (path) {
				path = strchr(path+2, '/');
				if (path)
					remote->path_len = strlen(path);
			}
			continue;
		}
		refspec = argv;
		nr_refspec = argc - i;
		break;
	}

#ifndef USE_CURL_MULTI
	die("git-push is not available for http/https repository when not compiled with USE_CURL_MULTI");
#endif

	if (!remote->url)
		usage(http_push_usage);

	if (delete_branch && nr_refspec != 1)
		die("You must specify only one branch name when deleting a remote branch");

	memset(remote_dir_exists, -1, 256);

	http_init(NULL);

	no_pragma_header = curl_slist_append(no_pragma_header, "Pragma:");

	if (remote->url && remote->url[strlen(remote->url)-1] != '/') {
		rewritten_url = xmalloc(strlen(remote->url)+2);
		strcpy(rewritten_url, remote->url);
		strcat(rewritten_url, "/");
		remote->url = rewritten_url;
		++remote->path_len;
	}

	/* Verify DAV compliance/lock support */
	if (!locking_available()) {
		rc = 1;
		goto cleanup;
	}

	signal(SIGINT, remove_locks_on_signal);
	signal(SIGHUP, remove_locks_on_signal);
	signal(SIGQUIT, remove_locks_on_signal);
	signal(SIGTERM, remove_locks_on_signal);

	/* Check whether the remote has server info files */
	remote->can_update_info_refs = 0;
	remote->has_info_refs = remote_exists("info/refs");
	remote->has_info_packs = remote_exists("objects/info/packs");
	if (remote->has_info_refs) {
		info_ref_lock = lock_remote("info/refs", LOCK_TIME);
		if (info_ref_lock)
			remote->can_update_info_refs = 1;
		else {
			fprintf(stderr, "Error: cannot lock existing info/refs\n");
			rc = 1;
			goto cleanup;
		}
	}
	if (remote->has_info_packs)
		fetch_indices();

	/* Get a list of all local and remote heads to validate refspecs */
	get_local_heads();
	fprintf(stderr, "Fetching remote heads...\n");
	get_dav_remote_heads();

	/* Remove a remote branch if -d or -D was specified */
	if (delete_branch) {
		if (delete_remote_branch(refspec[0], force_delete) == -1)
			fprintf(stderr, "Unable to delete remote branch %s\n",
				refspec[0]);
		goto cleanup;
	}

	/* match them up */
	if (!remote_tail)
		remote_tail = &remote_refs;
	if (match_refs(local_refs, remote_refs, &remote_tail,
		       nr_refspec, (const char **) refspec, push_all)) {
		rc = -1;
		goto cleanup;
	}
	if (!remote_refs) {
		fprintf(stderr, "No refs in common and none specified; doing nothing.\n");
		rc = 0;
		goto cleanup;
	}

	new_refs = 0;
	for (ref = remote_refs; ref; ref = ref->next) {
		char old_hex[60], *new_hex;
		const char *commit_argv[4];
		int commit_argc;
		char *new_sha1_hex, *old_sha1_hex;

		if (!ref->peer_ref)
			continue;

		if (is_zero_sha1(ref->peer_ref->new_sha1)) {
			if (delete_remote_branch(ref->name, 1) == -1) {
				error("Could not remove %s", ref->name);
				rc = -4;
			}
			new_refs++;
			continue;
		}

		if (!hashcmp(ref->old_sha1, ref->peer_ref->new_sha1)) {
			if (push_verbosely || 1)
				fprintf(stderr, "'%s': up-to-date\n", ref->name);
			continue;
		}

		if (!force_all &&
		    !is_zero_sha1(ref->old_sha1) &&
		    !ref->force) {
			if (!has_sha1_file(ref->old_sha1) ||
			    !ref_newer(ref->peer_ref->new_sha1,
				       ref->old_sha1)) {
				/*
				 * We do not have the remote ref, or
				 * we know that the remote ref is not
				 * an ancestor of what we are trying to
				 * push.  Either way this can be losing
				 * commits at the remote end and likely
				 * we were not up to date to begin with.
				 */
				error("remote '%s' is not an ancestor of\n"
				      "local '%s'.\n"
				      "Maybe you are not up-to-date and "
				      "need to pull first?",
				      ref->name,
				      ref->peer_ref->name);
				rc = -2;
				continue;
			}
		}
		hashcpy(ref->new_sha1, ref->peer_ref->new_sha1);
		new_refs++;
		strcpy(old_hex, sha1_to_hex(ref->old_sha1));
		new_hex = sha1_to_hex(ref->new_sha1);

		fprintf(stderr, "updating '%s'", ref->name);
		if (strcmp(ref->name, ref->peer_ref->name))
			fprintf(stderr, " using '%s'", ref->peer_ref->name);
		fprintf(stderr, "\n  from %s\n  to   %s\n", old_hex, new_hex);
		if (dry_run)
			continue;

		/* Lock remote branch ref */
		ref_lock = lock_remote(ref->name, LOCK_TIME);
		if (ref_lock == NULL) {
			fprintf(stderr, "Unable to lock remote branch %s\n",
				ref->name);
			rc = 1;
			continue;
		}

		/* Set up revision info for this refspec */
		commit_argc = 3;
		new_sha1_hex = xstrdup(sha1_to_hex(ref->new_sha1));
		old_sha1_hex = NULL;
		commit_argv[1] = "--objects";
		commit_argv[2] = new_sha1_hex;
		if (!push_all && !is_zero_sha1(ref->old_sha1)) {
			old_sha1_hex = xmalloc(42);
			sprintf(old_sha1_hex, "^%s",
				sha1_to_hex(ref->old_sha1));
			commit_argv[3] = old_sha1_hex;
			commit_argc++;
		}
		init_revisions(&revs, setup_git_directory());
		setup_revisions(commit_argc, commit_argv, &revs, NULL);
		revs.edge_hint = 0; /* just in case */
		free(new_sha1_hex);
		if (old_sha1_hex) {
			free(old_sha1_hex);
			commit_argv[1] = NULL;
		}

		/* Generate a list of objects that need to be pushed */
		pushing = 0;
		if (prepare_revision_walk(&revs))
			die("revision walk setup failed");
		mark_edges_uninteresting(revs.commits, &revs, NULL);
		objects_to_send = get_delta(&revs, ref_lock);
		finish_all_active_slots();

		/* Push missing objects to remote, this would be a
		   convenient time to pack them first if appropriate. */
		pushing = 1;
		if (objects_to_send)
			fprintf(stderr, "    sending %d objects\n",
				objects_to_send);
#ifdef USE_CURL_MULTI
		fill_active_slots();
		add_fill_function(NULL, fill_active_slot);
#endif
		do {
			finish_all_active_slots();
#ifdef USE_CURL_MULTI
			fill_active_slots();
#endif
		} while (request_queue_head && !aborted);

		/* Update the remote branch if all went well */
		if (aborted || !update_remote(ref->new_sha1, ref_lock))
			rc = 1;

		if (!rc)
			fprintf(stderr, "    done\n");
		unlock_remote(ref_lock);
		check_locks();
	}

	/* Update remote server info if appropriate */
	if (remote->has_info_refs && new_refs) {
		if (info_ref_lock && remote->can_update_info_refs) {
			fprintf(stderr, "Updating remote server info\n");
			if (!dry_run)
				update_remote_info_refs(info_ref_lock);
		} else {
			fprintf(stderr, "Unable to update server info\n");
		}
	}

 cleanup:
	free(rewritten_url);
	if (info_ref_lock)
		unlock_remote(info_ref_lock);
	free(remote);

	curl_slist_free_all(no_pragma_header);

	http_cleanup();

	request = request_queue_head;
	while (request != NULL) {
		next_request = request->next;
		release_request(request);
		request = next_request;
	}

	return rc;
}
#include "git-compat-util.h"
#include "environment.h"
#include "hex.h"
#include "repository.h"
#include "commit.h"
#include "tag.h"
#include "blob.h"
#include "http.h"
#include "diff.h"
#include "revision.h"
#include "remote.h"
#include "list-objects.h"
#include "setup.h"
#include "sigchain.h"
#include "strvec.h"
#include "tree.h"
#include "tree-walk.h"
#include "url.h"
#include "packfile.h"
#include "object-store-ll.h"
#include "commit-reach.h"

#ifdef EXPAT_NEEDS_XMLPARSE_H
#include <xmlparse.h>
#else
#include <expat.h>
#endif

static const char http_push_usage[] =
"git http-push [--all] [--dry-run] [--force] [--verbose] <remote> [<head>...]\n";

#ifndef XML_STATUS_OK
enum XML_Status {
  XML_STATUS_OK = 1,
  XML_STATUS_ERROR = 0
};
#define XML_STATUS_OK    1
#define XML_STATUS_ERROR 0
#endif

#define PREV_BUF_SIZE 4096

/* DAV methods */
#define DAV_LOCK "LOCK"
#define DAV_MKCOL "MKCOL"
#define DAV_MOVE "MOVE"
#define DAV_PROPFIND "PROPFIND"
#define DAV_PUT "PUT"
#define DAV_UNLOCK "UNLOCK"
#define DAV_DELETE "DELETE"

/* DAV lock flags */
#define DAV_PROP_LOCKWR (1u << 0)
#define DAV_PROP_LOCKEX (1u << 1)
#define DAV_LOCK_OK (1u << 2)

/* DAV XML properties */
#define DAV_CTX_LOCKENTRY ".multistatus.response.propstat.prop.supportedlock.lockentry"
#define DAV_CTX_LOCKTYPE_WRITE ".multistatus.response.propstat.prop.supportedlock.lockentry.locktype.write"
#define DAV_CTX_LOCKTYPE_EXCLUSIVE ".multistatus.response.propstat.prop.supportedlock.lockentry.lockscope.exclusive"
#define DAV_ACTIVELOCK_OWNER ".prop.lockdiscovery.activelock.owner.href"
#define DAV_ACTIVELOCK_TIMEOUT ".prop.lockdiscovery.activelock.timeout"
#define DAV_ACTIVELOCK_TOKEN ".prop.lockdiscovery.activelock.locktoken.href"
#define DAV_PROPFIND_RESP ".multistatus.response"
#define DAV_PROPFIND_NAME ".multistatus.response.href"
#define DAV_PROPFIND_COLLECTION ".multistatus.response.propstat.prop.resourcetype.collection"

/* DAV request body templates */
#define PROPFIND_SUPPORTEDLOCK_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:propfind xmlns:D=\"DAV:\">\n<D:prop xmlns:R=\"%s\">\n<D:supportedlock/>\n</D:prop>\n</D:propfind>"
#define PROPFIND_ALL_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:propfind xmlns:D=\"DAV:\">\n<D:allprop/>\n</D:propfind>"
#define LOCK_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:lockinfo xmlns:D=\"DAV:\">\n<D:lockscope><D:exclusive/></D:lockscope>\n<D:locktype><D:write/></D:locktype>\n<D:owner>\n<D:href>mailto:%s</D:href>\n</D:owner>\n</D:lockinfo>"

#define LOCK_TIME 600
#define LOCK_REFRESH 30

/* Remember to update object flag allocation in object.h */
#define LOCAL    (1u<<11)
#define REMOTE   (1u<<12)
#define FETCHING (1u<<13)
#define PUSHING  (1u<<14)

/* We allow "recursive" symbolic refs. Only within reason, though */
#define MAXDEPTH 5

static int pushing;
static int aborted;
static signed char remote_dir_exists[256];

static int push_verbosely;
static int push_all = MATCH_REFS_NONE;
static int force_all;
static int dry_run;
static int helper_status;

static struct object_list *objects;

struct repo {
	char *url;
	char *path;
	int path_len;
	int has_info_refs;
	int can_update_info_refs;
	int has_info_packs;
	struct packed_git *packs;
	struct remote_lock *locks;
};

static struct repo *repo;

enum transfer_state {
	NEED_FETCH,
	RUN_FETCH_LOOSE,
	RUN_FETCH_PACKED,
	NEED_PUSH,
	RUN_MKCOL,
	RUN_PUT,
	RUN_MOVE,
	ABORTED,
	COMPLETE
};

struct transfer_request {
	struct object *obj;
	struct packed_git *target;
	char *url;
	char *dest;
	struct remote_lock *lock;
	struct curl_slist *headers;
	struct buffer buffer;
	enum transfer_state state;
	CURLcode curl_result;
	char errorstr[CURL_ERROR_SIZE];
	long http_code;
	void *userData;
	struct active_request_slot *slot;
	struct transfer_request *next;
};

static struct transfer_request *request_queue_head;

struct xml_ctx {
	char *name;
	int len;
	char *cdata;
	void (*userFunc)(struct xml_ctx *ctx, int tag_closed);
	void *userData;
};

struct remote_lock {
	char *url;
	char *owner;
	char *token;
	char tmpfile_suffix[GIT_MAX_HEXSZ + 1];
	time_t start_time;
	long timeout;
	int refreshing;
	struct remote_lock *next;
};

/* Flags that control remote_ls processing */
#define PROCESS_FILES (1u << 0)
#define PROCESS_DIRS  (1u << 1)
#define RECURSIVE     (1u << 2)

/* Flags that remote_ls passes to callback functions */
#define IS_DIR (1u << 0)

struct remote_ls_ctx {
	char *path;
	void (*userFunc)(struct remote_ls_ctx *ls);
	void *userData;
	int flags;
	char *dentry_name;
	int dentry_flags;
	struct remote_ls_ctx *parent;
};

/* get_dav_token_headers options */
enum dav_header_flag {
	DAV_HEADER_IF = (1u << 0),
	DAV_HEADER_LOCK = (1u << 1),
	DAV_HEADER_TIMEOUT = (1u << 2)
};

static char *xml_entities(const char *s)
{
	struct strbuf buf = STRBUF_INIT;
	strbuf_addstr_xml_quoted(&buf, s);
	return strbuf_detach(&buf, NULL);
}

static void curl_setup_http_get(CURL *curl, const char *url,
		const char *custom_req)
{
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, custom_req);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite_null);
}

static void curl_setup_http(CURL *curl, const char *url,
		const char *custom_req, struct buffer *buffer,
		curl_write_callback write_fn)
{
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_INFILE, buffer);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE, buffer->buf.len);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, fread_buffer);
	curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, seek_buffer);
	curl_easy_setopt(curl, CURLOPT_SEEKDATA, buffer);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_fn);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 0);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, custom_req);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
}

static struct curl_slist *get_dav_token_headers(struct remote_lock *lock, enum dav_header_flag options)
{
	struct strbuf buf = STRBUF_INIT;
	struct curl_slist *dav_headers = http_copy_default_headers();

	if (options & DAV_HEADER_IF) {
		strbuf_addf(&buf, "If: (<%s>)", lock->token);
		dav_headers = curl_slist_append(dav_headers, buf.buf);
		strbuf_reset(&buf);
	}
	if (options & DAV_HEADER_LOCK) {
		strbuf_addf(&buf, "Lock-Token: <%s>", lock->token);
		dav_headers = curl_slist_append(dav_headers, buf.buf);
		strbuf_reset(&buf);
	}
	if (options & DAV_HEADER_TIMEOUT) {
		strbuf_addf(&buf, "Timeout: Second-%ld", lock->timeout);
		dav_headers = curl_slist_append(dav_headers, buf.buf);
		strbuf_reset(&buf);
	}
	strbuf_release(&buf);

	return dav_headers;
}

static void finish_request(struct transfer_request *request);
static void release_request(struct transfer_request *request);

static void process_response(void *callback_data)
{
	struct transfer_request *request =
		(struct transfer_request *)callback_data;

	finish_request(request);
}

static void start_fetch_loose(struct transfer_request *request)
{
	struct active_request_slot *slot;
	struct http_object_request *obj_req;

	obj_req = new_http_object_request(repo->url, &request->obj->oid);
	if (!obj_req) {
		request->state = ABORTED;
		return;
	}

	slot = obj_req->slot;
	slot->callback_func = process_response;
	slot->callback_data = request;
	request->slot = slot;
	request->userData = obj_req;

	/* Try to get the request started, abort the request on error */
	request->state = RUN_FETCH_LOOSE;
	if (!start_active_slot(slot)) {
		fprintf(stderr, "Unable to start GET request\n");
		repo->can_update_info_refs = 0;
		release_http_object_request(obj_req);
		release_request(request);
	}
}

static void start_mkcol(struct transfer_request *request)
{
	char *hex = oid_to_hex(&request->obj->oid);
	struct active_request_slot *slot;

	request->url = get_remote_object_url(repo->url, hex, 1);

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	curl_setup_http_get(slot->curl, request->url, DAV_MKCOL);
	curl_easy_setopt(slot->curl, CURLOPT_ERRORBUFFER, request->errorstr);

	if (start_active_slot(slot)) {
		request->slot = slot;
		request->state = RUN_MKCOL;
	} else {
		request->state = ABORTED;
		FREE_AND_NULL(request->url);
	}
}

static void start_fetch_packed(struct transfer_request *request)
{
	struct packed_git *target;

	struct transfer_request *check_request = request_queue_head;
	struct http_pack_request *preq;

	target = find_sha1_pack(request->obj->oid.hash, repo->packs);
	if (!target) {
		fprintf(stderr, "Unable to fetch %s, will not be able to update server info refs\n", oid_to_hex(&request->obj->oid));
		repo->can_update_info_refs = 0;
		release_request(request);
		return;
	}
	close_pack_index(target);
	request->target = target;

	fprintf(stderr,	"Fetching pack %s\n",
		hash_to_hex(target->hash));
	fprintf(stderr, " which contains %s\n", oid_to_hex(&request->obj->oid));

	preq = new_http_pack_request(target->hash, repo->url);
	if (!preq) {
		repo->can_update_info_refs = 0;
		return;
	}

	/* Make sure there isn't another open request for this pack */
	while (check_request) {
		if (check_request->state == RUN_FETCH_PACKED &&
		    !strcmp(check_request->url, preq->url)) {
			release_http_pack_request(preq);
			release_request(request);
			return;
		}
		check_request = check_request->next;
	}

	preq->slot->callback_func = process_response;
	preq->slot->callback_data = request;
	request->slot = preq->slot;
	request->userData = preq;

	/* Try to get the request started, abort the request on error */
	request->state = RUN_FETCH_PACKED;
	if (!start_active_slot(preq->slot)) {
		fprintf(stderr, "Unable to start GET request\n");
		release_http_pack_request(preq);
		repo->can_update_info_refs = 0;
		release_request(request);
	}
}

static void start_put(struct transfer_request *request)
{
	char *hex = oid_to_hex(&request->obj->oid);
	struct active_request_slot *slot;
	struct strbuf buf = STRBUF_INIT;
	enum object_type type;
	char hdr[50];
	void *unpacked;
	unsigned long len;
	int hdrlen;
	ssize_t size;
	git_zstream stream;

	unpacked = repo_read_object_file(the_repository, &request->obj->oid,
					 &type, &len);
	hdrlen = format_object_header(hdr, sizeof(hdr), type, len);

	/* Set it up */
	git_deflate_init(&stream, zlib_compression_level);
	size = git_deflate_bound(&stream, len + hdrlen);
	strbuf_init(&request->buffer.buf, size);
	request->buffer.posn = 0;

	/* Compress it */
	stream.next_out = (unsigned char *)request->buffer.buf.buf;
	stream.avail_out = size;

	/* First header.. */
	stream.next_in = (void *)hdr;
	stream.avail_in = hdrlen;
	while (git_deflate(&stream, 0) == Z_OK)
		; /* nothing */

	/* Then the data itself.. */
	stream.next_in = unpacked;
	stream.avail_in = len;
	while (git_deflate(&stream, Z_FINISH) == Z_OK)
		; /* nothing */
	git_deflate_end(&stream);
	free(unpacked);

	request->buffer.buf.len = stream.total_out;

	strbuf_addstr(&buf, "Destination: ");
	append_remote_object_url(&buf, repo->url, hex, 0);
	request->dest = strbuf_detach(&buf, NULL);

	append_remote_object_url(&buf, repo->url, hex, 0);
	strbuf_add(&buf, request->lock->tmpfile_suffix, the_hash_algo->hexsz + 1);
	request->url = strbuf_detach(&buf, NULL);

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	curl_setup_http(slot->curl, request->url, DAV_PUT,
			&request->buffer, fwrite_null);

	if (start_active_slot(slot)) {
		request->slot = slot;
		request->state = RUN_PUT;
	} else {
		request->state = ABORTED;
		FREE_AND_NULL(request->url);
	}
}

static void start_move(struct transfer_request *request)
{
	struct active_request_slot *slot;
	struct curl_slist *dav_headers = http_copy_default_headers();

	slot = get_active_slot();
	slot->callback_func = process_response;
	slot->callback_data = request;
	curl_setup_http_get(slot->curl, request->url, DAV_MOVE);
	dav_headers = curl_slist_append(dav_headers, request->dest);
	dav_headers = curl_slist_append(dav_headers, "Overwrite: T");
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		request->slot = slot;
		request->state = RUN_MOVE;
	} else {
		request->state = ABORTED;
		FREE_AND_NULL(request->url);
	}
}

static int refresh_lock(struct remote_lock *lock)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct curl_slist *dav_headers;
	int rc = 0;

	lock->refreshing = 1;

	dav_headers = get_dav_token_headers(lock, DAV_HEADER_IF | DAV_HEADER_TIMEOUT);

	slot = get_active_slot();
	slot->results = &results;
	curl_setup_http_get(slot->curl, lock->url, DAV_LOCK);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result != CURLE_OK) {
			fprintf(stderr, "LOCK HTTP error %ld\n",
				results.http_code);
		} else {
			lock->start_time = time(NULL);
			rc = 1;
		}
	}

	lock->refreshing = 0;
	curl_slist_free_all(dav_headers);

	return rc;
}

static void check_locks(void)
{
	struct remote_lock *lock = repo->locks;
	time_t current_time = time(NULL);
	int time_remaining;

	while (lock) {
		time_remaining = lock->start_time + lock->timeout -
			current_time;
		if (!lock->refreshing && time_remaining < LOCK_REFRESH) {
			if (!refresh_lock(lock)) {
				fprintf(stderr,
					"Unable to refresh lock for %s\n",
					lock->url);
				aborted = 1;
				return;
			}
		}
		lock = lock->next;
	}
}

static void release_request(struct transfer_request *request)
{
	struct transfer_request *entry = request_queue_head;

	if (request == request_queue_head) {
		request_queue_head = request->next;
	} else {
		while (entry && entry->next != request)
			entry = entry->next;
		if (entry)
			entry->next = request->next;
	}

	free(request->url);
	free(request);
}

static void finish_request(struct transfer_request *request)
{
	struct http_pack_request *preq;
	struct http_object_request *obj_req;

	request->curl_result = request->slot->curl_result;
	request->http_code = request->slot->http_code;
	request->slot = NULL;

	/* Keep locks active */
	check_locks();

	if (request->headers)
		curl_slist_free_all(request->headers);

	/* URL is reused for MOVE after PUT and used during FETCH */
	if (request->state != RUN_PUT && request->state != RUN_FETCH_PACKED) {
		FREE_AND_NULL(request->url);
	}

	if (request->state == RUN_MKCOL) {
		if (request->curl_result == CURLE_OK ||
		    request->http_code == 405) {
			remote_dir_exists[request->obj->oid.hash[0]] = 1;
			start_put(request);
		} else {
			fprintf(stderr, "MKCOL %s failed, aborting (%d/%ld)\n",
				oid_to_hex(&request->obj->oid),
				request->curl_result, request->http_code);
			request->state = ABORTED;
			aborted = 1;
		}
	} else if (request->state == RUN_PUT) {
		if (request->curl_result == CURLE_OK) {
			start_move(request);
		} else {
			fprintf(stderr,	"PUT %s failed, aborting (%d/%ld)\n",
				oid_to_hex(&request->obj->oid),
				request->curl_result, request->http_code);
			request->state = ABORTED;
			aborted = 1;
		}
	} else if (request->state == RUN_MOVE) {
		if (request->curl_result == CURLE_OK) {
			if (push_verbosely)
				fprintf(stderr, "    sent %s\n",
					oid_to_hex(&request->obj->oid));
			request->obj->flags |= REMOTE;
			release_request(request);
		} else {
			fprintf(stderr, "MOVE %s failed, aborting (%d/%ld)\n",
				oid_to_hex(&request->obj->oid),
				request->curl_result, request->http_code);
			request->state = ABORTED;
			aborted = 1;
		}
	} else if (request->state == RUN_FETCH_LOOSE) {
		obj_req = (struct http_object_request *)request->userData;

		if (finish_http_object_request(obj_req) == 0)
			if (obj_req->rename == 0)
				request->obj->flags |= (LOCAL | REMOTE);

		/* Try fetching packed if necessary */
		if (request->obj->flags & LOCAL) {
			release_http_object_request(obj_req);
			release_request(request);
		} else
			start_fetch_packed(request);

	} else if (request->state == RUN_FETCH_PACKED) {
		int fail = 1;
		if (request->curl_result != CURLE_OK) {
			fprintf(stderr, "Unable to get pack file %s\n%s",
				request->url, curl_errorstr);
		} else {
			preq = (struct http_pack_request *)request->userData;

			if (preq) {
				if (finish_http_pack_request(preq) == 0)
					fail = 0;
				release_http_pack_request(preq);
			}
		}
		if (fail)
			repo->can_update_info_refs = 0;
		else
			http_install_packfile(request->target, &repo->packs);
		release_request(request);
	}
}

static int is_running_queue;
static int fill_active_slot(void *data UNUSED)
{
	struct transfer_request *request;

	if (aborted || !is_running_queue)
		return 0;

	for (request = request_queue_head; request; request = request->next) {
		if (request->state == NEED_FETCH) {
			start_fetch_loose(request);
			return 1;
		} else if (pushing && request->state == NEED_PUSH) {
			if (remote_dir_exists[request->obj->oid.hash[0]] == 1) {
				start_put(request);
			} else {
				start_mkcol(request);
			}
			return 1;
		}
	}
	return 0;
}

static void get_remote_object_list(unsigned char parent);

static void add_fetch_request(struct object *obj)
{
	struct transfer_request *request;

	check_locks();

	/*
	 * Don't fetch the object if it's known to exist locally
	 * or is already in the request queue
	 */
	if (remote_dir_exists[obj->oid.hash[0]] == -1)
		get_remote_object_list(obj->oid.hash[0]);
	if (obj->flags & (LOCAL | FETCHING))
		return;

	obj->flags |= FETCHING;
	request = xmalloc(sizeof(*request));
	request->obj = obj;
	request->url = NULL;
	request->lock = NULL;
	request->headers = NULL;
	request->state = NEED_FETCH;
	request->next = request_queue_head;
	request_queue_head = request;

	fill_active_slots();
	step_active_slots();
}

static int add_send_request(struct object *obj, struct remote_lock *lock)
{
	struct transfer_request *request;
	struct packed_git *target;

	/* Keep locks active */
	check_locks();

	/*
	 * Don't push the object if it's known to exist on the remote
	 * or is already in the request queue
	 */
	if (remote_dir_exists[obj->oid.hash[0]] == -1)
		get_remote_object_list(obj->oid.hash[0]);
	if (obj->flags & (REMOTE | PUSHING))
		return 0;
	target = find_sha1_pack(obj->oid.hash, repo->packs);
	if (target) {
		obj->flags |= REMOTE;
		return 0;
	}

	obj->flags |= PUSHING;
	request = xmalloc(sizeof(*request));
	request->obj = obj;
	request->url = NULL;
	request->lock = lock;
	request->headers = NULL;
	request->state = NEED_PUSH;
	request->next = request_queue_head;
	request_queue_head = request;

	fill_active_slots();
	step_active_slots();

	return 1;
}

static int fetch_indices(void)
{
	int ret;

	if (push_verbosely)
		fprintf(stderr, "Getting pack list\n");

	switch (http_get_info_packs(repo->url, &repo->packs)) {
	case HTTP_OK:
	case HTTP_MISSING_TARGET:
		ret = 0;
		break;
	default:
		ret = -1;
	}

	return ret;
}

static void one_remote_object(const struct object_id *oid)
{
	struct object *obj;

	obj = lookup_object(the_repository, oid);
	if (!obj)
		obj = parse_object(the_repository, oid);

	/* Ignore remote objects that don't exist locally */
	if (!obj)
		return;

	obj->flags |= REMOTE;
	if (!object_list_contains(objects, obj))
		object_list_insert(obj, &objects);
}

static void handle_lockprop_ctx(struct xml_ctx *ctx, int tag_closed)
{
	int *lock_flags = (int *)ctx->userData;

	if (tag_closed) {
		if (!strcmp(ctx->name, DAV_CTX_LOCKENTRY)) {
			if ((*lock_flags & DAV_PROP_LOCKEX) &&
			    (*lock_flags & DAV_PROP_LOCKWR)) {
				*lock_flags |= DAV_LOCK_OK;
			}
			*lock_flags &= DAV_LOCK_OK;
		} else if (!strcmp(ctx->name, DAV_CTX_LOCKTYPE_WRITE)) {
			*lock_flags |= DAV_PROP_LOCKWR;
		} else if (!strcmp(ctx->name, DAV_CTX_LOCKTYPE_EXCLUSIVE)) {
			*lock_flags |= DAV_PROP_LOCKEX;
		}
	}
}

static void handle_new_lock_ctx(struct xml_ctx *ctx, int tag_closed)
{
	struct remote_lock *lock = (struct remote_lock *)ctx->userData;
	git_hash_ctx hash_ctx;
	unsigned char lock_token_hash[GIT_MAX_RAWSZ];

	if (tag_closed && ctx->cdata) {
		if (!strcmp(ctx->name, DAV_ACTIVELOCK_OWNER)) {
			lock->owner = xstrdup(ctx->cdata);
		} else if (!strcmp(ctx->name, DAV_ACTIVELOCK_TIMEOUT)) {
			const char *arg;
			if (skip_prefix(ctx->cdata, "Second-", &arg))
				lock->timeout = strtol(arg, NULL, 10);
		} else if (!strcmp(ctx->name, DAV_ACTIVELOCK_TOKEN)) {
			lock->token = xstrdup(ctx->cdata);

			the_hash_algo->init_fn(&hash_ctx);
			the_hash_algo->update_fn(&hash_ctx, lock->token, strlen(lock->token));
			the_hash_algo->final_fn(lock_token_hash, &hash_ctx);

			lock->tmpfile_suffix[0] = '_';
			memcpy(lock->tmpfile_suffix + 1, hash_to_hex(lock_token_hash), the_hash_algo->hexsz);
		}
	}
}

static void one_remote_ref(const char *refname);

static void
xml_start_tag(void *userData, const char *name, const char **atts UNUSED)
{
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
	const char *c = strchr(name, ':');
	int old_namelen, new_len;

	if (!c)
		c = name;
	else
		c++;

	old_namelen = strlen(ctx->name);
	new_len = old_namelen + strlen(c) + 2;

	if (new_len > ctx->len) {
		ctx->name = xrealloc(ctx->name, new_len);
		ctx->len = new_len;
	}
	xsnprintf(ctx->name + old_namelen, ctx->len - old_namelen, ".%s", c);

	FREE_AND_NULL(ctx->cdata);

	ctx->userFunc(ctx, 0);
}

static void
xml_end_tag(void *userData, const char *name)
{
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
	const char *c = strchr(name, ':');
	char *ep;

	ctx->userFunc(ctx, 1);

	if (!c)
		c = name;
	else
		c++;

	ep = ctx->name + strlen(ctx->name) - strlen(c) - 1;
	*ep = 0;
}

static void
xml_cdata(void *userData, const XML_Char *s, int len)
{
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
	free(ctx->cdata);
	ctx->cdata = xmemdupz(s, len);
}

static struct remote_lock *lock_remote(const char *path, long timeout)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct strbuf in_buffer = STRBUF_INIT;
	char *url;
	char *ep;
	char timeout_header[25];
	struct remote_lock *lock = NULL;
	struct curl_slist *dav_headers = http_copy_default_headers();
	struct xml_ctx ctx;
	char *escaped;

	url = xstrfmt("%s%s", repo->url, path);

	/* Make sure leading directories exist for the remote ref */
	ep = strchr(url + strlen(repo->url) + 1, '/');
	while (ep) {
		char saved_character = ep[1];
		ep[1] = '\0';
		slot = get_active_slot();
		slot->results = &results;
		curl_setup_http_get(slot->curl, url, DAV_MKCOL);
		if (start_active_slot(slot)) {
			run_active_slot(slot);
			if (results.curl_result != CURLE_OK &&
			    results.http_code != 405) {
				fprintf(stderr,
					"Unable to create branch path %s\n",
					url);
				free(url);
				return NULL;
			}
		} else {
			fprintf(stderr, "Unable to start MKCOL request\n");
			free(url);
			return NULL;
		}
		ep[1] = saved_character;
		ep = strchr(ep + 1, '/');
	}

	escaped = xml_entities(ident_default_email());
	strbuf_addf(&out_buffer.buf, LOCK_REQUEST, escaped);
	free(escaped);

	xsnprintf(timeout_header, sizeof(timeout_header), "Timeout: Second-%ld", timeout);
	dav_headers = curl_slist_append(dav_headers, timeout_header);
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");

	slot = get_active_slot();
	slot->results = &results;
	curl_setup_http(slot->curl, url, DAV_LOCK, &out_buffer, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEDATA, &in_buffer);

	CALLOC_ARRAY(lock, 1);
	lock->timeout = -1;

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK) {
			XML_Parser parser = XML_ParserCreate(NULL);
			enum XML_Status result;
			ctx.name = xcalloc(10, 1);
			ctx.len = 0;
			ctx.cdata = NULL;
			ctx.userFunc = handle_new_lock_ctx;
			ctx.userData = lock;
			XML_SetUserData(parser, &ctx);
			XML_SetElementHandler(parser, xml_start_tag,
					      xml_end_tag);
			XML_SetCharacterDataHandler(parser, xml_cdata);
			result = XML_Parse(parser, in_buffer.buf,
					   in_buffer.len, 1);
			free(ctx.name);
			if (result != XML_STATUS_OK) {
				fprintf(stderr, "XML error: %s\n",
					XML_ErrorString(
						XML_GetErrorCode(parser)));
				lock->timeout = -1;
			}
			XML_ParserFree(parser);
		} else {
			fprintf(stderr,
				"error: curl result=%d, HTTP code=%ld\n",
				results.curl_result, results.http_code);
		}
	} else {
		fprintf(stderr, "Unable to start LOCK request\n");
	}

	curl_slist_free_all(dav_headers);
	strbuf_release(&out_buffer.buf);
	strbuf_release(&in_buffer);

	if (lock->token == NULL || lock->timeout <= 0) {
		free(lock->token);
		free(lock->owner);
		free(url);
		FREE_AND_NULL(lock);
	} else {
		lock->url = url;
		lock->start_time = time(NULL);
		lock->next = repo->locks;
		repo->locks = lock;
	}

	return lock;
}

static int unlock_remote(struct remote_lock *lock)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct remote_lock *prev = repo->locks;
	struct curl_slist *dav_headers;
	int rc = 0;

	dav_headers = get_dav_token_headers(lock, DAV_HEADER_LOCK);

	slot = get_active_slot();
	slot->results = &results;
	curl_setup_http_get(slot->curl, lock->url, DAV_UNLOCK);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK)
			rc = 1;
		else
			fprintf(stderr, "UNLOCK HTTP error %ld\n",
				results.http_code);
	} else {
		fprintf(stderr, "Unable to start UNLOCK request\n");
	}

	curl_slist_free_all(dav_headers);

	if (repo->locks == lock) {
		repo->locks = lock->next;
	} else {
		while (prev && prev->next != lock)
			prev = prev->next;
		if (prev)
			prev->next = lock->next;
	}

	free(lock->owner);
	free(lock->url);
	free(lock->token);
	free(lock);

	return rc;
}

static void remove_locks(void)
{
	struct remote_lock *lock = repo->locks;

	fprintf(stderr, "Removing remote locks...\n");
	while (lock) {
		struct remote_lock *next = lock->next;
		unlock_remote(lock);
		lock = next;
	}
}

static void remove_locks_on_signal(int signo)
{
	remove_locks();
	sigchain_pop(signo);
	raise(signo);
}

static void remote_ls(const char *path, int flags,
		      void (*userFunc)(struct remote_ls_ctx *ls),
		      void *userData);

/* extract hex from sharded "xx/x{38}" filename */
static int get_oid_hex_from_objpath(const char *path, struct object_id *oid)
{
	oid->algo = hash_algo_by_ptr(the_hash_algo);

	if (strlen(path) != the_hash_algo->hexsz + 1)
		return -1;

	if (hex_to_bytes(oid->hash, path, 1))
		return -1;
	path += 2;
	path++; /* skip '/' */

	return hex_to_bytes(oid->hash + 1, path, the_hash_algo->rawsz - 1);
}

static void process_ls_object(struct remote_ls_ctx *ls)
{
	unsigned int *parent = (unsigned int *)ls->userData;
	const char *path = ls->dentry_name;
	struct object_id oid;

	if (!strcmp(ls->path, ls->dentry_name) && (ls->flags & IS_DIR)) {
		remote_dir_exists[*parent] = 1;
		return;
	}

	if (!skip_prefix(path, "objects/", &path) ||
	    get_oid_hex_from_objpath(path, &oid))
		return;

	one_remote_object(&oid);
}

static void process_ls_ref(struct remote_ls_ctx *ls)
{
	if (!strcmp(ls->path, ls->dentry_name) && (ls->dentry_flags & IS_DIR)) {
		fprintf(stderr, "  %s\n", ls->dentry_name);
		return;
	}

	if (!(ls->dentry_flags & IS_DIR))
		one_remote_ref(ls->dentry_name);
}

static void handle_remote_ls_ctx(struct xml_ctx *ctx, int tag_closed)
{
	struct remote_ls_ctx *ls = (struct remote_ls_ctx *)ctx->userData;

	if (tag_closed) {
		if (!strcmp(ctx->name, DAV_PROPFIND_RESP) && ls->dentry_name) {
			if (ls->dentry_flags & IS_DIR) {

				/* ensure collection names end with slash */
				str_end_url_with_slash(ls->dentry_name, &ls->dentry_name);

				if (ls->flags & PROCESS_DIRS) {
					ls->userFunc(ls);
				}
				if (strcmp(ls->dentry_name, ls->path) &&
				    ls->flags & RECURSIVE) {
					remote_ls(ls->dentry_name,
						  ls->flags,
						  ls->userFunc,
						  ls->userData);
				}
			} else if (ls->flags & PROCESS_FILES) {
				ls->userFunc(ls);
			}
		} else if (!strcmp(ctx->name, DAV_PROPFIND_NAME) && ctx->cdata) {
			char *path = ctx->cdata;
			if (*ctx->cdata == 'h') {
				path = strstr(path, "//");
				if (path) {
					path = strchr(path+2, '/');
				}
			}
			if (path) {
				const char *url = repo->url;
				if (repo->path)
					url = repo->path;
				if (strncmp(path, url, repo->path_len))
					error("Parsed path '%s' does not match url: '%s'",
					      path, url);
				else {
					path += repo->path_len;
					ls->dentry_name = xstrdup(path);
				}
			}
		} else if (!strcmp(ctx->name, DAV_PROPFIND_COLLECTION)) {
			ls->dentry_flags |= IS_DIR;
		}
	} else if (!strcmp(ctx->name, DAV_PROPFIND_RESP)) {
		FREE_AND_NULL(ls->dentry_name);
		ls->dentry_flags = 0;
	}
}

/*
 * NEEDSWORK: remote_ls() ignores info/refs on the remote side.  But it
 * should _only_ heed the information from that file, instead of trying to
 * determine the refs from the remote file system (badly: it does not even
 * know about packed-refs).
 */
static void remote_ls(const char *path, int flags,
		      void (*userFunc)(struct remote_ls_ctx *ls),
		      void *userData)
{
	char *url = xstrfmt("%s%s", repo->url, path);
	struct active_request_slot *slot;
	struct slot_results results;
	struct strbuf in_buffer = STRBUF_INIT;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct curl_slist *dav_headers = http_copy_default_headers();
	struct xml_ctx ctx;
	struct remote_ls_ctx ls;

	ls.flags = flags;
	ls.path = xstrdup(path);
	ls.dentry_name = NULL;
	ls.dentry_flags = 0;
	ls.userData = userData;
	ls.userFunc = userFunc;

	strbuf_addstr(&out_buffer.buf, PROPFIND_ALL_REQUEST);

	dav_headers = curl_slist_append(dav_headers, "Depth: 1");
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");

	slot = get_active_slot();
	slot->results = &results;
	curl_setup_http(slot->curl, url, DAV_PROPFIND,
			&out_buffer, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEDATA, &in_buffer);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK) {
			XML_Parser parser = XML_ParserCreate(NULL);
			enum XML_Status result;
			ctx.name = xcalloc(10, 1);
			ctx.len = 0;
			ctx.cdata = NULL;
			ctx.userFunc = handle_remote_ls_ctx;
			ctx.userData = &ls;
			XML_SetUserData(parser, &ctx);
			XML_SetElementHandler(parser, xml_start_tag,
					      xml_end_tag);
			XML_SetCharacterDataHandler(parser, xml_cdata);
			result = XML_Parse(parser, in_buffer.buf,
					   in_buffer.len, 1);
			free(ctx.name);

			if (result != XML_STATUS_OK) {
				fprintf(stderr, "XML error: %s\n",
					XML_ErrorString(
						XML_GetErrorCode(parser)));
			}
			XML_ParserFree(parser);
		}
	} else {
		fprintf(stderr, "Unable to start PROPFIND request\n");
	}

	free(ls.path);
	free(url);
	strbuf_release(&out_buffer.buf);
	strbuf_release(&in_buffer);
	curl_slist_free_all(dav_headers);
}

static void get_remote_object_list(unsigned char parent)
{
	char path[] = "objects/XX/";
	static const char hex[] = "0123456789abcdef";
	unsigned int val = parent;

	path[8] = hex[val >> 4];
	path[9] = hex[val & 0xf];
	remote_dir_exists[val] = 0;
	remote_ls(path, (PROCESS_FILES | PROCESS_DIRS),
		  process_ls_object, &val);
}

static int locking_available(void)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct strbuf in_buffer = STRBUF_INIT;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct curl_slist *dav_headers = http_copy_default_headers();
	struct xml_ctx ctx;
	int lock_flags = 0;
	char *escaped;

	escaped = xml_entities(repo->url);
	strbuf_addf(&out_buffer.buf, PROPFIND_SUPPORTEDLOCK_REQUEST, escaped);
	free(escaped);

	dav_headers = curl_slist_append(dav_headers, "Depth: 0");
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");

	slot = get_active_slot();
	slot->results = &results;
	curl_setup_http(slot->curl, repo->url, DAV_PROPFIND,
			&out_buffer, fwrite_buffer);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEDATA, &in_buffer);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		if (results.curl_result == CURLE_OK) {
			XML_Parser parser = XML_ParserCreate(NULL);
			enum XML_Status result;
			ctx.name = xcalloc(10, 1);
			ctx.len = 0;
			ctx.cdata = NULL;
			ctx.userFunc = handle_lockprop_ctx;
			ctx.userData = &lock_flags;
			XML_SetUserData(parser, &ctx);
			XML_SetElementHandler(parser, xml_start_tag,
					      xml_end_tag);
			result = XML_Parse(parser, in_buffer.buf,
					   in_buffer.len, 1);
			free(ctx.name);

			if (result != XML_STATUS_OK) {
				fprintf(stderr, "XML error: %s\n",
					XML_ErrorString(
						XML_GetErrorCode(parser)));
				lock_flags = 0;
			}
			XML_ParserFree(parser);
			if (!lock_flags)
				error("no DAV locking support on %s",
				      repo->url);

		} else {
			error("Cannot access URL %s, return code %d",
			      repo->url, results.curl_result);
			lock_flags = 0;
		}
	} else {
		error("Unable to start PROPFIND request on %s", repo->url);
	}

	strbuf_release(&out_buffer.buf);
	strbuf_release(&in_buffer);
	curl_slist_free_all(dav_headers);

	return lock_flags;
}

static struct object_list **add_one_object(struct object *obj, struct object_list **p)
{
	struct object_list *entry = xmalloc(sizeof(struct object_list));
	entry->item = obj;
	entry->next = *p;
	*p = entry;
	return &entry->next;
}

static struct object_list **process_blob(struct blob *blob,
					 struct object_list **p)
{
	struct object *obj = &blob->object;

	obj->flags |= LOCAL;

	if (obj->flags & (UNINTERESTING | SEEN))
		return p;

	obj->flags |= SEEN;
	return add_one_object(obj, p);
}

static struct object_list **process_tree(struct tree *tree,
					 struct object_list **p)
{
	struct object *obj = &tree->object;
	struct tree_desc desc;
	struct name_entry entry;

	obj->flags |= LOCAL;

	if (obj->flags & (UNINTERESTING | SEEN))
		return p;
	if (parse_tree(tree) < 0)
		die("bad tree object %s", oid_to_hex(&obj->oid));

	obj->flags |= SEEN;
	p = add_one_object(obj, p);

	init_tree_desc(&desc, &tree->object.oid, tree->buffer, tree->size);

	while (tree_entry(&desc, &entry))
		switch (object_type(entry.mode)) {
		case OBJ_TREE:
			p = process_tree(lookup_tree(the_repository, &entry.oid),
					 p);
			break;
		case OBJ_BLOB:
			p = process_blob(lookup_blob(the_repository, &entry.oid),
					 p);
			break;
		default:
			/* Subproject commit - not in this repository */
			break;
		}

	free_tree_buffer(tree);
	return p;
}

static int get_delta(struct rev_info *revs, struct remote_lock *lock)
{
	int i;
	struct commit *commit;
	struct object_list **p = &objects;
	int count = 0;

	while ((commit = get_revision(revs)) != NULL) {
		p = process_tree(repo_get_commit_tree(the_repository, commit),
				 p);
		commit->object.flags |= LOCAL;
		if (!(commit->object.flags & UNINTERESTING))
			count += add_send_request(&commit->object, lock);
	}

	for (i = 0; i < revs->pending.nr; i++) {
		struct object_array_entry *entry = revs->pending.objects + i;
		struct object *obj = entry->item;
		const char *name = entry->name;

		if (obj->flags & (UNINTERESTING | SEEN))
			continue;
		if (obj->type == OBJ_TAG) {
			obj->flags |= SEEN;
			p = add_one_object(obj, p);
			continue;
		}
		if (obj->type == OBJ_TREE) {
			p = process_tree((struct tree *)obj, p);
			continue;
		}
		if (obj->type == OBJ_BLOB) {
			p = process_blob((struct blob *)obj, p);
			continue;
		}
		die("unknown pending object %s (%s)", oid_to_hex(&obj->oid), name);
	}

	while (objects) {
		if (!(objects->item->flags & UNINTERESTING))
			count += add_send_request(objects->item, lock);
		objects = objects->next;
	}

	return count;
}

static int update_remote(const struct object_id *oid, struct remote_lock *lock)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct curl_slist *dav_headers;

	dav_headers = get_dav_token_headers(lock, DAV_HEADER_IF);

	strbuf_addf(&out_buffer.buf, "%s\n", oid_to_hex(oid));

	slot = get_active_slot();
	slot->results = &results;
	curl_setup_http(slot->curl, lock->url, DAV_PUT,
			&out_buffer, fwrite_null);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	if (start_active_slot(slot)) {
		run_active_slot(slot);
		strbuf_release(&out_buffer.buf);
		if (results.curl_result != CURLE_OK) {
			fprintf(stderr,
				"PUT error: curl result=%d, HTTP code=%ld\n",
				results.curl_result, results.http_code);
			/* We should attempt recovery? */
			return 0;
		}
	} else {
		strbuf_release(&out_buffer.buf);
		fprintf(stderr, "Unable to start PUT request\n");
		return 0;
	}

	return 1;
}

static struct ref *remote_refs;

static void one_remote_ref(const char *refname)
{
	struct ref *ref;
	struct object *obj;

	ref = alloc_ref(refname);

	if (http_fetch_ref(repo->url, ref) != 0) {
		fprintf(stderr,
			"Unable to fetch ref %s from %s\n",
			refname, repo->url);
		free(ref);
		return;
	}

	/*
	 * Fetch a copy of the object if it doesn't exist locally - it
	 * may be required for updating server info later.
	 */
	if (repo->can_update_info_refs && !repo_has_object_file(the_repository, &ref->old_oid)) {
		obj = lookup_unknown_object(the_repository, &ref->old_oid);
		fprintf(stderr,	"  fetch %s for %s\n",
			oid_to_hex(&ref->old_oid), refname);
		add_fetch_request(obj);
	}

	ref->next = remote_refs;
	remote_refs = ref;
}

static void get_dav_remote_heads(void)
{
	remote_ls("refs/", (PROCESS_FILES | PROCESS_DIRS | RECURSIVE), process_ls_ref, NULL);
}

static void add_remote_info_ref(struct remote_ls_ctx *ls)
{
	struct strbuf *buf = (struct strbuf *)ls->userData;
	struct object *o;
	struct ref *ref;

	ref = alloc_ref(ls->dentry_name);

	if (http_fetch_ref(repo->url, ref) != 0) {
		fprintf(stderr,
			"Unable to fetch ref %s from %s\n",
			ls->dentry_name, repo->url);
		aborted = 1;
		free(ref);
		return;
	}

	o = parse_object(the_repository, &ref->old_oid);
	if (!o) {
		fprintf(stderr,
			"Unable to parse object %s for remote ref %s\n",
			oid_to_hex(&ref->old_oid), ls->dentry_name);
		aborted = 1;
		free(ref);
		return;
	}

	strbuf_addf(buf, "%s\t%s\n",
		    oid_to_hex(&ref->old_oid), ls->dentry_name);

	if (o->type == OBJ_TAG) {
		o = deref_tag(the_repository, o, ls->dentry_name, 0);
		if (o)
			strbuf_addf(buf, "%s\t%s^{}\n",
				    oid_to_hex(&o->oid), ls->dentry_name);
	}
	free(ref);
}

static void update_remote_info_refs(struct remote_lock *lock)
{
	struct buffer buffer = { STRBUF_INIT, 0 };
	struct active_request_slot *slot;
	struct slot_results results;
	struct curl_slist *dav_headers;

	remote_ls("refs/", (PROCESS_FILES | RECURSIVE),
		  add_remote_info_ref, &buffer.buf);
	if (!aborted) {
		dav_headers = get_dav_token_headers(lock, DAV_HEADER_IF);

		slot = get_active_slot();
		slot->results = &results;
		curl_setup_http(slot->curl, lock->url, DAV_PUT,
				&buffer, fwrite_null);
		curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

		if (start_active_slot(slot)) {
			run_active_slot(slot);
			if (results.curl_result != CURLE_OK) {
				fprintf(stderr,
					"PUT error: curl result=%d, HTTP code=%ld\n",
					results.curl_result, results.http_code);
			}
		}
	}
	strbuf_release(&buffer.buf);
}

static int remote_exists(const char *path)
{
	char *url = xstrfmt("%s%s", repo->url, path);
	int ret;


	switch (http_get_strbuf(url, NULL, NULL)) {
	case HTTP_OK:
		ret = 1;
		break;
	case HTTP_MISSING_TARGET:
		ret = 0;
		break;
	case HTTP_ERROR:
		error("unable to access '%s': %s", url, curl_errorstr);
		/* fallthrough */
	default:
		ret = -1;
	}
	free(url);
	return ret;
}

static void fetch_symref(const char *path, char **symref, struct object_id *oid)
{
	char *url = xstrfmt("%s%s", repo->url, path);
	struct strbuf buffer = STRBUF_INIT;
	const char *name;

	if (http_get_strbuf(url, &buffer, NULL) != HTTP_OK)
		die("Couldn't get %s for remote symref\n%s", url,
		    curl_errorstr);
	free(url);

	FREE_AND_NULL(*symref);
	oidclr(oid);

	if (buffer.len == 0)
		return;

	/* Cut off trailing newline. */
	strbuf_rtrim(&buffer);

	/* If it's a symref, set the refname; otherwise try for a sha1 */
	if (skip_prefix(buffer.buf, "ref: ", &name)) {
		*symref = xmemdupz(name, buffer.len - (name - buffer.buf));
	} else {
		get_oid_hex(buffer.buf, oid);
	}

	strbuf_release(&buffer);
}

static int verify_merge_base(struct object_id *head_oid, struct ref *remote)
{
	struct commit *head = lookup_commit_or_die(head_oid, "HEAD");
	struct commit *branch = lookup_commit_or_die(&remote->old_oid,
						     remote->name);
	int ret = repo_in_merge_bases(the_repository, branch, head);

	if (ret < 0)
		exit(128);
	return ret;
}

static int delete_remote_branch(const char *pattern, int force)
{
	struct ref *refs = remote_refs;
	struct ref *remote_ref = NULL;
	struct object_id head_oid;
	char *symref = NULL;
	int match;
	int patlen = strlen(pattern);
	int i;
	struct active_request_slot *slot;
	struct slot_results results;
	char *url;

	/* Find the remote branch(es) matching the specified branch name */
	for (match = 0; refs; refs = refs->next) {
		char *name = refs->name;
		int namelen = strlen(name);
		if (namelen < patlen ||
		    memcmp(name + namelen - patlen, pattern, patlen))
			continue;
		if (namelen != patlen && name[namelen - patlen - 1] != '/')
			continue;
		match++;
		remote_ref = refs;
	}
	if (match == 0)
		return error("No remote branch matches %s", pattern);
	if (match != 1)
		return error("More than one remote branch matches %s",
			     pattern);

	/*
	 * Remote HEAD must be a symref (not exactly foolproof; a remote
	 * symlink to a symref will look like a symref)
	 */
	fetch_symref("HEAD", &symref, &head_oid);
	if (!symref)
		return error("Remote HEAD is not a symref");

	/* Remote branch must not be the remote HEAD */
	for (i = 0; symref && i < MAXDEPTH; i++) {
		if (!strcmp(remote_ref->name, symref))
			return error("Remote branch %s is the current HEAD",
				     remote_ref->name);
		fetch_symref(symref, &symref, &head_oid);
	}

	/* Run extra sanity checks if delete is not forced */
	if (!force) {
		/* Remote HEAD must resolve to a known object */
		if (symref)
			return error("Remote HEAD symrefs too deep");
		if (is_null_oid(&head_oid))
			return error("Unable to resolve remote HEAD");
		if (!repo_has_object_file(the_repository, &head_oid))
			return error("Remote HEAD resolves to object %s\nwhich does not exist locally, perhaps you need to fetch?", oid_to_hex(&head_oid));

		/* Remote branch must resolve to a known object */
		if (is_null_oid(&remote_ref->old_oid))
			return error("Unable to resolve remote branch %s",
				     remote_ref->name);
		if (!repo_has_object_file(the_repository, &remote_ref->old_oid))
			return error("Remote branch %s resolves to object %s\nwhich does not exist locally, perhaps you need to fetch?", remote_ref->name, oid_to_hex(&remote_ref->old_oid));

		/* Remote branch must be an ancestor of remote HEAD */
		if (!verify_merge_base(&head_oid, remote_ref)) {
			return error("The branch '%s' is not an ancestor "
				     "of your current HEAD.\n"
				     "If you are sure you want to delete it,"
				     " run:\n\t'git http-push -D %s %s'",
				     remote_ref->name, repo->url, pattern);
		}
	}

	/* Send delete request */
	fprintf(stderr, "Removing remote branch '%s'\n", remote_ref->name);
	if (dry_run)
		return 0;
	url = xstrfmt("%s%s", repo->url, remote_ref->name);
	slot = get_active_slot();
	slot->results = &results;
	curl_setup_http_get(slot->curl, url, DAV_DELETE);
	if (start_active_slot(slot)) {
		run_active_slot(slot);
		free(url);
		if (results.curl_result != CURLE_OK)
			return error("DELETE request failed (%d/%ld)",
				     results.curl_result, results.http_code);
	} else {
		free(url);
		return error("Unable to start DELETE request");
	}

	return 0;
}

static void run_request_queue(void)
{
	is_running_queue = 1;
	fill_active_slots();
	add_fill_function(NULL, fill_active_slot);
	do {
		finish_all_active_slots();
		fill_active_slots();
	} while (request_queue_head && !aborted);

	is_running_queue = 0;
}

int cmd_main(int argc, const char **argv)
{
	struct transfer_request *request;
	struct transfer_request *next_request;
	struct refspec rs = REFSPEC_INIT_PUSH;
	struct remote_lock *ref_lock = NULL;
	struct remote_lock *info_ref_lock = NULL;
	int delete_branch = 0;
	int force_delete = 0;
	int objects_to_send;
	int rc = 0;
	int i;
	int new_refs;
	struct ref *ref, *local_refs;

	CALLOC_ARRAY(repo, 1);

	argv++;
	for (i = 1; i < argc; i++, argv++) {
		const char *arg = *argv;

		if (*arg == '-') {
			if (!strcmp(arg, "--all")) {
				push_all = MATCH_REFS_ALL;
				continue;
			}
			if (!strcmp(arg, "--force")) {
				force_all = 1;
				continue;
			}
			if (!strcmp(arg, "--dry-run")) {
				dry_run = 1;
				continue;
			}
			if (!strcmp(arg, "--helper-status")) {
				helper_status = 1;
				continue;
			}
			if (!strcmp(arg, "--verbose")) {
				push_verbosely = 1;
				http_is_verbose = 1;
				continue;
			}
			if (!strcmp(arg, "-d")) {
				delete_branch = 1;
				continue;
			}
			if (!strcmp(arg, "-D")) {
				delete_branch = 1;
				force_delete = 1;
				continue;
			}
			if (!strcmp(arg, "-h"))
				usage(http_push_usage);
		}
		if (!repo->url) {
			char *path = strstr(arg, "//");
			str_end_url_with_slash(arg, &repo->url);
			repo->path_len = strlen(repo->url);
			if (path) {
				repo->path = strchr(path+2, '/');
				if (repo->path)
					repo->path_len = strlen(repo->path);
			}
			continue;
		}
		refspec_appendn(&rs, argv, argc - i);
		break;
	}

	if (!repo->url)
		usage(http_push_usage);

	if (delete_branch && rs.nr != 1)
		die("You must specify only one branch name when deleting a remote branch");

	setup_git_directory();

	memset(remote_dir_exists, -1, 256);

	http_init(NULL, repo->url, 1);

	is_running_queue = 0;

	/* Verify DAV compliance/lock support */
	if (!locking_available()) {
		rc = 1;
		goto cleanup;
	}

	sigchain_push_common(remove_locks_on_signal);

	/* Check whether the remote has server info files */
	repo->can_update_info_refs = 0;
	repo->has_info_refs = remote_exists("info/refs");
	repo->has_info_packs = remote_exists("objects/info/packs");
	if (repo->has_info_refs) {
		info_ref_lock = lock_remote("info/refs", LOCK_TIME);
		if (info_ref_lock)
			repo->can_update_info_refs = 1;
		else {
			error("cannot lock existing info/refs");
			rc = 1;
			goto cleanup;
		}
	}
	if (repo->has_info_packs)
		fetch_indices();

	/* Get a list of all local and remote heads to validate refspecs */
	local_refs = get_local_heads();
	fprintf(stderr, "Fetching remote heads...\n");
	get_dav_remote_heads();
	run_request_queue();

	/* Remove a remote branch if -d or -D was specified */
	if (delete_branch) {
		const char *branch = rs.items[i].src;
		if (delete_remote_branch(branch, force_delete) == -1) {
			fprintf(stderr, "Unable to delete remote branch %s\n",
				branch);
			if (helper_status)
				printf("error %s cannot remove\n", branch);
		}
		goto cleanup;
	}

	/* match them up */
	if (match_push_refs(local_refs, &remote_refs, &rs, push_all)) {
		rc = -1;
		goto cleanup;
	}
	if (!remote_refs) {
		fprintf(stderr, "No refs in common and none specified; doing nothing.\n");
		if (helper_status)
			printf("error null no match\n");
		rc = 0;
		goto cleanup;
	}

	new_refs = 0;
	for (ref = remote_refs; ref; ref = ref->next) {
		struct rev_info revs;
		struct strvec commit_argv = STRVEC_INIT;

		if (!ref->peer_ref)
			continue;

		if (is_null_oid(&ref->peer_ref->new_oid)) {
			if (delete_remote_branch(ref->name, 1) == -1) {
				error("Could not remove %s", ref->name);
				if (helper_status)
					printf("error %s cannot remove\n", ref->name);
				rc = -4;
			}
			else if (helper_status)
				printf("ok %s\n", ref->name);
			new_refs++;
			continue;
		}

		if (oideq(&ref->old_oid, &ref->peer_ref->new_oid)) {
			if (push_verbosely)
				/* stable plumbing output; do not modify or localize */
				fprintf(stderr, "'%s': up-to-date\n", ref->name);
			if (helper_status)
				printf("ok %s up to date\n", ref->name);
			continue;
		}

		if (!force_all &&
		    !is_null_oid(&ref->old_oid) &&
		    !ref->force) {
			if (!repo_has_object_file(the_repository, &ref->old_oid) ||
			    !ref_newer(&ref->peer_ref->new_oid,
				       &ref->old_oid)) {
				/*
				 * We do not have the remote ref, or
				 * we know that the remote ref is not
				 * an ancestor of what we are trying to
				 * push.  Either way this can be losing
				 * commits at the remote end and likely
				 * we were not up to date to begin with.
				 */
				/* stable plumbing output; do not modify or localize */
				error("remote '%s' is not an ancestor of\n"
				      "local '%s'.\n"
				      "Maybe you are not up-to-date and "
				      "need to pull first?",
				      ref->name,
				      ref->peer_ref->name);
				if (helper_status)
					printf("error %s non-fast forward\n", ref->name);
				rc = -2;
				continue;
			}
		}
		oidcpy(&ref->new_oid, &ref->peer_ref->new_oid);
		new_refs++;

		fprintf(stderr, "updating '%s'", ref->name);
		if (strcmp(ref->name, ref->peer_ref->name))
			fprintf(stderr, " using '%s'", ref->peer_ref->name);
		fprintf(stderr, "\n  from %s\n  to   %s\n",
			oid_to_hex(&ref->old_oid), oid_to_hex(&ref->new_oid));
		if (dry_run) {
			if (helper_status)
				printf("ok %s\n", ref->name);
			continue;
		}

		/* Lock remote branch ref */
		ref_lock = lock_remote(ref->name, LOCK_TIME);
		if (!ref_lock) {
			fprintf(stderr, "Unable to lock remote branch %s\n",
				ref->name);
			if (helper_status)
				printf("error %s lock error\n", ref->name);
			rc = 1;
			continue;
		}

		/* Set up revision info for this refspec */
		strvec_push(&commit_argv, ""); /* ignored */
		strvec_push(&commit_argv, "--objects");
		strvec_push(&commit_argv, oid_to_hex(&ref->new_oid));
		if (!push_all && !is_null_oid(&ref->old_oid))
			strvec_pushf(&commit_argv, "^%s",
				     oid_to_hex(&ref->old_oid));
		repo_init_revisions(the_repository, &revs, setup_git_directory());
		setup_revisions(commit_argv.nr, commit_argv.v, &revs, NULL);
		revs.edge_hint = 0; /* just in case */

		/* Generate a list of objects that need to be pushed */
		pushing = 0;
		if (prepare_revision_walk(&revs))
			die("revision walk setup failed");
		mark_edges_uninteresting(&revs, NULL, 0);
		objects_to_send = get_delta(&revs, ref_lock);
		finish_all_active_slots();

		/* Push missing objects to remote, this would be a
		   convenient time to pack them first if appropriate. */
		pushing = 1;
		if (objects_to_send)
			fprintf(stderr, "    sending %d objects\n",
				objects_to_send);

		run_request_queue();

		/* Update the remote branch if all went well */
		if (aborted || !update_remote(&ref->new_oid, ref_lock))
			rc = 1;

		if (!rc)
			fprintf(stderr, "    done\n");
		if (helper_status)
			printf("%s %s\n", !rc ? "ok" : "error", ref->name);
		unlock_remote(ref_lock);
		check_locks();
		strvec_clear(&commit_argv);
		release_revisions(&revs);
	}

	/* Update remote server info if appropriate */
	if (repo->has_info_refs && new_refs) {
		if (info_ref_lock && repo->can_update_info_refs) {
			fprintf(stderr, "Updating remote server info\n");
			if (!dry_run)
				update_remote_info_refs(info_ref_lock);
		} else {
			fprintf(stderr, "Unable to update server info\n");
		}
	}

 cleanup:
	if (info_ref_lock)
		unlock_remote(info_ref_lock);
	free(repo);

	http_cleanup();

	request = request_queue_head;
	while (request != NULL) {
		next_request = request->next;
		release_request(request);
		request = next_request;
	}

	return rc;
}
#include "cache.h"
#include "add-interactive.h"
#include "color.h"
#include "config.h"
#include "diffcore.h"
#include "revision.h"
#include "refs.h"
#include "string-list.h"
#include "lockfile.h"
#include "dir.h"
#include "run-command.h"
#include "prompt.h"

static void init_color(struct repository *r, struct add_i_state *s,
		       const char *section_and_slot, char *dst,
		       const char *default_color)
{
	char *key = xstrfmt("color.%s", section_and_slot);
	const char *value;

	if (!s->use_color)
		dst[0] = '\0';
	else if (repo_config_get_value(r, key, &value) ||
		 color_parse(value, dst))
		strlcpy(dst, default_color, COLOR_MAXLEN);

	free(key);
}

void init_add_i_state(struct add_i_state *s, struct repository *r)
{
	const char *value;

	s->r = r;

	if (repo_config_get_value(r, "color.interactive", &value))
		s->use_color = -1;
	else
		s->use_color =
			git_config_colorbool("color.interactive", value);
	s->use_color = want_color(s->use_color);

	init_color(r, s, "interactive.header", s->header_color, GIT_COLOR_BOLD);
	init_color(r, s, "interactive.help", s->help_color, GIT_COLOR_BOLD_RED);
	init_color(r, s, "interactive.prompt", s->prompt_color,
		   GIT_COLOR_BOLD_BLUE);
	init_color(r, s, "interactive.error", s->error_color,
		   GIT_COLOR_BOLD_RED);

	init_color(r, s, "diff.frag", s->fraginfo_color,
		   diff_get_color(s->use_color, DIFF_FRAGINFO));
	init_color(r, s, "diff.context", s->context_color, "fall back");
	if (!strcmp(s->context_color, "fall back"))
		init_color(r, s, "diff.plain", s->context_color,
			   diff_get_color(s->use_color, DIFF_CONTEXT));
	init_color(r, s, "diff.old", s->file_old_color,
		diff_get_color(s->use_color, DIFF_FILE_OLD));
	init_color(r, s, "diff.new", s->file_new_color,
		diff_get_color(s->use_color, DIFF_FILE_NEW));

	strlcpy(s->reset_color,
		s->use_color ? GIT_COLOR_RESET : "", COLOR_MAXLEN);

	FREE_AND_NULL(s->interactive_diff_filter);
	git_config_get_string("interactive.difffilter",
			      &s->interactive_diff_filter);

	FREE_AND_NULL(s->interactive_diff_algorithm);
	git_config_get_string("diff.algorithm",
			      &s->interactive_diff_algorithm);

	git_config_get_bool("interactive.singlekey", &s->use_single_key);
}

void clear_add_i_state(struct add_i_state *s)
{
	FREE_AND_NULL(s->interactive_diff_filter);
	FREE_AND_NULL(s->interactive_diff_algorithm);
	memset(s, 0, sizeof(*s));
	s->use_color = -1;
}

/*
 * A "prefix item list" is a list of items that are identified by a string, and
 * a unique prefix (if any) is determined for each item.
 *
 * It is implemented in the form of a pair of `string_list`s, the first one
 * duplicating the strings, with the `util` field pointing at a structure whose
 * first field must be `size_t prefix_length`.
 *
 * That `prefix_length` field will be computed by `find_unique_prefixes()`; It
 * will be set to zero if no valid, unique prefix could be found.
 *
 * The second `string_list` is called `sorted` and does _not_ duplicate the
 * strings but simply reuses the first one's, with the `util` field pointing at
 * the `string_item_list` of the first `string_list`. It  will be populated and
 * sorted by `find_unique_prefixes()`.
 */
struct prefix_item_list {
	struct string_list items;
	struct string_list sorted;
	int *selected; /* for multi-selections */
	size_t min_length, max_length;
};
#define PREFIX_ITEM_LIST_INIT \
	{ STRING_LIST_INIT_DUP, STRING_LIST_INIT_NODUP, NULL, 1, 4 }

static void prefix_item_list_clear(struct prefix_item_list *list)
{
	string_list_clear(&list->items, 1);
	string_list_clear(&list->sorted, 0);
	FREE_AND_NULL(list->selected);
}

static void extend_prefix_length(struct string_list_item *p,
				 const char *other_string, size_t max_length)
{
	size_t *len = p->util;

	if (!*len || memcmp(p->string, other_string, *len))
		return;

	for (;;) {
		char c = p->string[*len];

		/*
		 * Is `p` a strict prefix of `other`? Or have we exhausted the
		 * maximal length of the prefix? Or is the current character a
		 * multi-byte UTF-8 one? If so, there is no valid, unique
		 * prefix.
		 */
		if (!c || ++*len > max_length || !isascii(c)) {
			*len = 0;
			break;
		}

		if (c != other_string[*len - 1])
			break;
	}
}

static void find_unique_prefixes(struct prefix_item_list *list)
{
	size_t i;

	if (list->sorted.nr == list->items.nr)
		return;

	string_list_clear(&list->sorted, 0);
	/* Avoid reallocating incrementally */
	list->sorted.items = xmalloc(st_mult(sizeof(*list->sorted.items),
					     list->items.nr));
	list->sorted.nr = list->sorted.alloc = list->items.nr;

	for (i = 0; i < list->items.nr; i++) {
		list->sorted.items[i].string = list->items.items[i].string;
		list->sorted.items[i].util = list->items.items + i;
	}

	string_list_sort(&list->sorted);

	for (i = 0; i < list->sorted.nr; i++) {
		struct string_list_item *sorted_item = list->sorted.items + i;
		struct string_list_item *item = sorted_item->util;
		size_t *len = item->util;

		*len = 0;
		while (*len < list->min_length) {
			char c = item->string[(*len)++];

			if (!c || !isascii(c)) {
				*len = 0;
				break;
			}
		}

		if (i > 0)
			extend_prefix_length(item, sorted_item[-1].string,
					     list->max_length);
		if (i + 1 < list->sorted.nr)
			extend_prefix_length(item, sorted_item[1].string,
					     list->max_length);
	}
}

static ssize_t find_unique(const char *string, struct prefix_item_list *list)
{
	int index = string_list_find_insert_index(&list->sorted, string, 1);
	struct string_list_item *item;

	if (list->items.nr != list->sorted.nr)
		BUG("prefix_item_list in inconsistent state (%"PRIuMAX
		    " vs %"PRIuMAX")",
		    (uintmax_t)list->items.nr, (uintmax_t)list->sorted.nr);

	if (index < 0)
		item = list->sorted.items[-1 - index].util;
	else if (index > 0 &&
		 starts_with(list->sorted.items[index - 1].string, string))
		return -1;
	else if (index + 1 < list->sorted.nr &&
		 starts_with(list->sorted.items[index + 1].string, string))
		return -1;
	else if (index < list->sorted.nr &&
		 starts_with(list->sorted.items[index].string, string))
		item = list->sorted.items[index].util;
	else
		return -1;
	return item - list->items.items;
}

struct list_options {
	int columns;
	const char *header;
	void (*print_item)(int i, int selected, struct string_list_item *item,
			   void *print_item_data);
	void *print_item_data;
};

static void list(struct add_i_state *s, struct string_list *list, int *selected,
		 struct list_options *opts)
{
	int i, last_lf = 0;

	if (!list->nr)
		return;

	if (opts->header)
		color_fprintf_ln(stdout, s->header_color,
				 "%s", opts->header);

	for (i = 0; i < list->nr; i++) {
		opts->print_item(i, selected ? selected[i] : 0, list->items + i,
				 opts->print_item_data);

		if ((opts->columns) && ((i + 1) % (opts->columns))) {
			putchar('\t');
			last_lf = 0;
		}
		else {
			putchar('\n');
			last_lf = 1;
		}
	}

	if (!last_lf)
		putchar('\n');
}
struct list_and_choose_options {
	struct list_options list_opts;

	const char *prompt;
	enum {
		SINGLETON = (1<<0),
		IMMEDIATE = (1<<1),
	} flags;
	void (*print_help)(struct add_i_state *s);
};

#define LIST_AND_CHOOSE_ERROR (-1)
#define LIST_AND_CHOOSE_QUIT  (-2)

/*
 * Returns the selected index in singleton mode, the number of selected items
 * otherwise.
 *
 * If an error occurred, returns `LIST_AND_CHOOSE_ERROR`. Upon EOF,
 * `LIST_AND_CHOOSE_QUIT` is returned.
 */
static ssize_t list_and_choose(struct add_i_state *s,
			       struct prefix_item_list *items,
			       struct list_and_choose_options *opts)
{
	int singleton = opts->flags & SINGLETON;
	int immediate = opts->flags & IMMEDIATE;

	struct strbuf input = STRBUF_INIT;
	ssize_t res = singleton ? LIST_AND_CHOOSE_ERROR : 0;

	if (!singleton) {
		free(items->selected);
		CALLOC_ARRAY(items->selected, items->items.nr);
	}

	if (singleton && !immediate)
		BUG("singleton requires immediate");

	find_unique_prefixes(items);

	for (;;) {
		char *p;

		strbuf_reset(&input);

		list(s, &items->items, items->selected, &opts->list_opts);

		color_fprintf(stdout, s->prompt_color, "%s", opts->prompt);
		fputs(singleton ? "> " : ">> ", stdout);
		fflush(stdout);

		if (git_read_line_interactively(&input) == EOF) {
			putchar('\n');
			if (immediate)
				res = LIST_AND_CHOOSE_QUIT;
			break;
		}

		if (!input.len)
			break;

		if (!strcmp(input.buf, "?")) {
			opts->print_help(s);
			continue;
		}

		p = input.buf;
		for (;;) {
			size_t sep = strcspn(p, " \t\r\n,");
			int choose = 1;
			/* `from` is inclusive, `to` is exclusive */
			ssize_t from = -1, to = -1;

			if (!sep) {
				if (!*p)
					break;
				p++;
				continue;
			}

			/* Input that begins with '-'; de-select */
			if (*p == '-') {
				choose = 0;
				p++;
				sep--;
			}

			if (sep == 1 && *p == '*') {
				from = 0;
				to = items->items.nr;
			} else if (isdigit(*p)) {
				char *endp;
				/*
				 * A range can be specified like 5-7 or 5-.
				 *
				 * Note: `from` is 0-based while the user input
				 * is 1-based, hence we have to decrement by
				 * one. We do not have to decrement `to` even
				 * if it is 0-based because it is an exclusive
				 * boundary.
				 */
				from = strtoul(p, &endp, 10) - 1;
				if (endp == p + sep)
					to = from + 1;
				else if (*endp == '-') {
					if (isdigit(*(++endp)))
						to = strtoul(endp, &endp, 10);
					else
						to = items->items.nr;
					/* extra characters after the range? */
					if (endp != p + sep)
						from = -1;
				}
			}

			if (p[sep])
				p[sep++] = '\0';
			if (from < 0) {
				from = find_unique(p, items);
				if (from >= 0)
					to = from + 1;
			}

			if (from < 0 || from >= items->items.nr ||
			    (singleton && from + 1 != to)) {
				color_fprintf_ln(stderr, s->error_color,
						 _("Huh (%s)?"), p);
				break;
			} else if (singleton) {
				res = from;
				break;
			}

			if (to > items->items.nr)
				to = items->items.nr;

			for (; from < to; from++)
				if (items->selected[from] != choose) {
					items->selected[from] = choose;
					res += choose ? +1 : -1;
				}

			p += sep;
		}

		if ((immediate && res != LIST_AND_CHOOSE_ERROR) ||
		    !strcmp(input.buf, "*"))
			break;
	}

	strbuf_release(&input);
	return res;
}

struct adddel {
	uintmax_t add, del;
	unsigned seen:1, unmerged:1, binary:1;
};

struct file_item {
	size_t prefix_length;
	struct adddel index, worktree;
};

static void add_file_item(struct string_list *files, const char *name)
{
	struct file_item *item = xcalloc(1, sizeof(*item));

	string_list_append(files, name)->util = item;
}

struct pathname_entry {
	struct hashmap_entry ent;
	const char *name;
	struct file_item *item;
};

static int pathname_entry_cmp(const void *unused_cmp_data,
			      const struct hashmap_entry *he1,
			      const struct hashmap_entry *he2,
			      const void *name)
{
	const struct pathname_entry *e1 =
		container_of(he1, const struct pathname_entry, ent);
	const struct pathname_entry *e2 =
		container_of(he2, const struct pathname_entry, ent);

	return strcmp(e1->name, name ? (const char *)name : e2->name);
}

struct collection_status {
	enum { FROM_WORKTREE = 0, FROM_INDEX = 1 } mode;

	const char *reference;

	unsigned skip_unseen:1;
	size_t unmerged_count, binary_count;
	struct string_list *files;
	struct hashmap file_map;
};

static void collect_changes_cb(struct diff_queue_struct *q,
			       struct diff_options *options,
			       void *data)
{
	struct collection_status *s = data;
	struct diffstat_t stat = { 0 };
	int i;

	if (!q->nr)
		return;

	compute_diffstat(options, &stat, q);

	for (i = 0; i < stat.nr; i++) {
		const char *name = stat.files[i]->name;
		int hash = strhash(name);
		struct pathname_entry *entry;
		struct file_item *file_item;
		struct adddel *adddel, *other_adddel;

		entry = hashmap_get_entry_from_hash(&s->file_map, hash, name,
						    struct pathname_entry, ent);
		if (!entry) {
			if (s->skip_unseen)
				continue;

			add_file_item(s->files, name);

			entry = xcalloc(1, sizeof(*entry));
			hashmap_entry_init(&entry->ent, hash);
			entry->name = s->files->items[s->files->nr - 1].string;
			entry->item = s->files->items[s->files->nr - 1].util;
			hashmap_add(&s->file_map, &entry->ent);
		}

		file_item = entry->item;
		adddel = s->mode == FROM_INDEX ?
			&file_item->index : &file_item->worktree;
		other_adddel = s->mode == FROM_INDEX ?
			&file_item->worktree : &file_item->index;
		adddel->seen = 1;
		adddel->add = stat.files[i]->added;
		adddel->del = stat.files[i]->deleted;
		if (stat.files[i]->is_binary) {
			if (!other_adddel->binary)
				s->binary_count++;
			adddel->binary = 1;
		}
		if (stat.files[i]->is_unmerged) {
			if (!other_adddel->unmerged)
				s->unmerged_count++;
			adddel->unmerged = 1;
		}
	}
	free_diffstat_info(&stat);
}

enum modified_files_filter {
	NO_FILTER = 0,
	WORKTREE_ONLY = 1,
	INDEX_ONLY = 2,
};

static int get_modified_files(struct repository *r,
			      enum modified_files_filter filter,
			      struct prefix_item_list *files,
			      const struct pathspec *ps,
			      size_t *unmerged_count,
			      size_t *binary_count)
{
	struct object_id head_oid;
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING,
					     &head_oid, NULL);
	struct collection_status s = { 0 };
	int i;

	if (discard_index(r->index) < 0 ||
	    repo_read_index_preload(r, ps, 0) < 0)
		return error(_("could not read index"));

	prefix_item_list_clear(files);
	s.files = &files->items;
	hashmap_init(&s.file_map, pathname_entry_cmp, NULL, 0);

	for (i = 0; i < 2; i++) {
		struct rev_info rev;
		struct setup_revision_opt opt = { 0 };

		if (filter == INDEX_ONLY)
			s.mode = (i == 0) ? FROM_INDEX : FROM_WORKTREE;
		else
			s.mode = (i == 0) ? FROM_WORKTREE : FROM_INDEX;
		s.skip_unseen = filter && i;

		opt.def = is_initial ?
			empty_tree_oid_hex() : oid_to_hex(&head_oid);

		init_revisions(&rev, NULL);
		setup_revisions(0, NULL, &rev, &opt);

		rev.diffopt.output_format = DIFF_FORMAT_CALLBACK;
		rev.diffopt.format_callback = collect_changes_cb;
		rev.diffopt.format_callback_data = &s;

		if (ps)
			copy_pathspec(&rev.prune_data, ps);

		if (s.mode == FROM_INDEX)
			run_diff_index(&rev, 1);
		else {
			rev.diffopt.flags.ignore_dirty_submodules = 1;
			run_diff_files(&rev, 0);
		}

		if (ps)
			clear_pathspec(&rev.prune_data);
	}
	hashmap_clear_and_free(&s.file_map, struct pathname_entry, ent);
	if (unmerged_count)
		*unmerged_count = s.unmerged_count;
	if (binary_count)
		*binary_count = s.binary_count;

	/* While the diffs are ordered already, we ran *two* diffs... */
	string_list_sort(&files->items);

	return 0;
}

static void render_adddel(struct strbuf *buf,
				struct adddel *ad, const char *no_changes)
{
	if (ad->binary)
		strbuf_addstr(buf, _("binary"));
	else if (ad->seen)
		strbuf_addf(buf, "+%"PRIuMAX"/-%"PRIuMAX,
			    (uintmax_t)ad->add, (uintmax_t)ad->del);
	else
		strbuf_addstr(buf, no_changes);
}

/* filters out prefixes which have special meaning to list_and_choose() */
static int is_valid_prefix(const char *prefix, size_t prefix_len)
{
	return prefix_len && prefix &&
		/*
		 * We expect `prefix` to be NUL terminated, therefore this
		 * `strcspn()` call is okay, even if it might do much more
		 * work than strictly necessary.
		 */
		strcspn(prefix, " \t\r\n,") >= prefix_len &&	/* separators */
		*prefix != '-' &&				/* deselection */
		!isdigit(*prefix) &&				/* selection */
		(prefix_len != 1 ||
		 (*prefix != '*' &&				/* "all" wildcard */
		  *prefix != '?'));				/* prompt help */
}

struct print_file_item_data {
	const char *modified_fmt, *color, *reset;
	struct strbuf buf, name, index, worktree;
	unsigned only_names:1;
};

static void print_file_item(int i, int selected, struct string_list_item *item,
			    void *print_file_item_data)
{
	struct file_item *c = item->util;
	struct print_file_item_data *d = print_file_item_data;
	const char *highlighted = NULL;

	strbuf_reset(&d->index);
	strbuf_reset(&d->worktree);
	strbuf_reset(&d->buf);

	/* Format the item with the prefix highlighted. */
	if (c->prefix_length > 0 &&
	    is_valid_prefix(item->string, c->prefix_length)) {
		strbuf_reset(&d->name);
		strbuf_addf(&d->name, "%s%.*s%s%s", d->color,
			    (int)c->prefix_length, item->string, d->reset,
			    item->string + c->prefix_length);
		highlighted = d->name.buf;
	}

	if (d->only_names) {
		printf("%c%2d: %s", selected ? '*' : ' ', i + 1,
		       highlighted ? highlighted : item->string);
		return;
	}

	render_adddel(&d->worktree, &c->worktree, _("nothing"));
	render_adddel(&d->index, &c->index, _("unchanged"));

	strbuf_addf(&d->buf, d->modified_fmt, d->index.buf, d->worktree.buf,
		    highlighted ? highlighted : item->string);

	printf("%c%2d: %s", selected ? '*' : ' ', i + 1, d->buf.buf);
}

static int run_status(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	if (get_modified_files(s->r, NO_FILTER, files, ps, NULL, NULL) < 0)
		return -1;

	list(s, &files->items, NULL, &opts->list_opts);
	putchar('\n');

	return 0;
}

static int run_update(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	int res = 0, fd;
	size_t count, i;
	struct lock_file index_lock;

	if (get_modified_files(s->r, WORKTREE_ONLY, files, ps, NULL, NULL) < 0)
		return -1;

	if (!files->items.nr) {
		putchar('\n');
		return 0;
	}

	opts->prompt = N_("Update");
	count = list_and_choose(s, files, opts);
	if (count <= 0) {
		putchar('\n');
		return 0;
	}

	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	if (fd < 0) {
		putchar('\n');
		return -1;
	}

	for (i = 0; i < files->items.nr; i++) {
		const char *name = files->items.items[i].string;
		if (files->selected[i] &&
		    add_file_to_index(s->r->index, name, 0) < 0) {
			res = error(_("could not stage '%s'"), name);
			break;
		}
	}

	if (!res && write_locked_index(s->r->index, &index_lock, COMMIT_LOCK) < 0)
		res = error(_("could not write index"));

	if (!res)
		printf(Q_("updated %d path\n",
			  "updated %d paths\n", count), (int)count);

	putchar('\n');
	return res;
}

static void revert_from_diff(struct diff_queue_struct *q,
			     struct diff_options *opt, void *data)
{
	int i, add_flags = ADD_CACHE_OK_TO_ADD | ADD_CACHE_OK_TO_REPLACE;

	for (i = 0; i < q->nr; i++) {
		struct diff_filespec *one = q->queue[i]->one;
		struct cache_entry *ce;

		if (!(one->mode && !is_null_oid(&one->oid))) {
			remove_file_from_index(opt->repo->index, one->path);
			printf(_("note: %s is untracked now.\n"), one->path);
		} else {
			ce = make_cache_entry(opt->repo->index, one->mode,
					      &one->oid, one->path, 0, 0);
			if (!ce)
				die(_("make_cache_entry failed for path '%s'"),
				    one->path);
			add_index_entry(opt->repo->index, ce, add_flags);
		}
	}
}

static int run_revert(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	int res = 0, fd;
	size_t count, i, j;

	struct object_id oid;
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &oid,
					     NULL);
	struct lock_file index_lock;
	const char **paths;
	struct tree *tree;
	struct diff_options diffopt = { NULL };

	if (get_modified_files(s->r, INDEX_ONLY, files, ps, NULL, NULL) < 0)
		return -1;

	if (!files->items.nr) {
		putchar('\n');
		return 0;
	}

	opts->prompt = N_("Revert");
	count = list_and_choose(s, files, opts);
	if (count <= 0)
		goto finish_revert;

	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	if (fd < 0) {
		res = -1;
		goto finish_revert;
	}

	if (is_initial)
		oidcpy(&oid, s->r->hash_algo->empty_tree);
	else {
		tree = parse_tree_indirect(&oid);
		if (!tree) {
			res = error(_("Could not parse HEAD^{tree}"));
			goto finish_revert;
		}
		oidcpy(&oid, &tree->object.oid);
	}

	ALLOC_ARRAY(paths, count + 1);
	for (i = j = 0; i < files->items.nr; i++)
		if (files->selected[i])
			paths[j++] = files->items.items[i].string;
	paths[j] = NULL;

	parse_pathspec(&diffopt.pathspec, 0,
		       PATHSPEC_PREFER_FULL | PATHSPEC_LITERAL_PATH,
		       NULL, paths);

	diffopt.output_format = DIFF_FORMAT_CALLBACK;
	diffopt.format_callback = revert_from_diff;
	diffopt.flags.override_submodule_config = 1;
	diffopt.repo = s->r;

	if (do_diff_cache(&oid, &diffopt))
		res = -1;
	else {
		diffcore_std(&diffopt);
		diff_flush(&diffopt);
	}
	free(paths);
	clear_pathspec(&diffopt.pathspec);

	if (!res && write_locked_index(s->r->index, &index_lock,
				       COMMIT_LOCK) < 0)
		res = -1;
	else
		res = repo_refresh_and_write_index(s->r, REFRESH_QUIET, 0, 1,
						   NULL, NULL, NULL);

	if (!res)
		printf(Q_("reverted %d path\n",
			  "reverted %d paths\n", count), (int)count);

finish_revert:
	putchar('\n');
	return res;
}

static int get_untracked_files(struct repository *r,
			       struct prefix_item_list *files,
			       const struct pathspec *ps)
{
	struct dir_struct dir = { 0 };
	size_t i;
	struct strbuf buf = STRBUF_INIT;

	if (repo_read_index(r) < 0)
		return error(_("could not read index"));

	prefix_item_list_clear(files);
	setup_standard_excludes(&dir);
	add_pattern_list(&dir, EXC_CMDL, "--exclude option");
	fill_directory(&dir, r->index, ps);

	for (i = 0; i < dir.nr; i++) {
		struct dir_entry *ent = dir.entries[i];

		if (index_name_is_other(r->index, ent->name, ent->len)) {
			strbuf_reset(&buf);
			strbuf_add(&buf, ent->name, ent->len);
			add_file_item(&files->items, buf.buf);
		}
	}

	strbuf_release(&buf);
	return 0;
}

static int run_add_untracked(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	struct print_file_item_data *d = opts->list_opts.print_item_data;
	int res = 0, fd;
	size_t count, i;
	struct lock_file index_lock;

	if (get_untracked_files(s->r, files, ps) < 0)
		return -1;

	if (!files->items.nr) {
		printf(_("No untracked files.\n"));
		goto finish_add_untracked;
	}

	opts->prompt = N_("Add untracked");
	d->only_names = 1;
	count = list_and_choose(s, files, opts);
	d->only_names = 0;
	if (count <= 0)
		goto finish_add_untracked;

	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	if (fd < 0) {
		res = -1;
		goto finish_add_untracked;
	}

	for (i = 0; i < files->items.nr; i++) {
		const char *name = files->items.items[i].string;
		if (files->selected[i] &&
		    add_file_to_index(s->r->index, name, 0) < 0) {
			res = error(_("could not stage '%s'"), name);
			break;
		}
	}

	if (!res &&
	    write_locked_index(s->r->index, &index_lock, COMMIT_LOCK) < 0)
		res = error(_("could not write index"));

	if (!res)
		printf(Q_("added %d path\n",
			  "added %d paths\n", count), (int)count);

finish_add_untracked:
	putchar('\n');
	return res;
}

static int run_patch(struct add_i_state *s, const struct pathspec *ps,
		     struct prefix_item_list *files,
		     struct list_and_choose_options *opts)
{
	int res = 0;
	ssize_t count, i, j;
	size_t unmerged_count = 0, binary_count = 0;

	if (get_modified_files(s->r, WORKTREE_ONLY, files, ps,
			       &unmerged_count, &binary_count) < 0)
		return -1;

	if (unmerged_count || binary_count) {
		for (i = j = 0; i < files->items.nr; i++) {
			struct file_item *item = files->items.items[i].util;

			if (item->index.binary || item->worktree.binary) {
				free(item);
				free(files->items.items[i].string);
			} else if (item->index.unmerged ||
				 item->worktree.unmerged) {
				color_fprintf_ln(stderr, s->error_color,
						 _("ignoring unmerged: %s"),
						 files->items.items[i].string);
				free(item);
				free(files->items.items[i].string);
			} else
				files->items.items[j++] = files->items.items[i];
		}
		files->items.nr = j;
	}

	if (!files->items.nr) {
		if (binary_count)
			fprintf(stderr, _("Only binary files changed.\n"));
		else
			fprintf(stderr, _("No changes.\n"));
		return 0;
	}

	opts->prompt = N_("Patch update");
	count = list_and_choose(s, files, opts);
	if (count > 0) {
		struct strvec args = STRVEC_INIT;
		struct pathspec ps_selected = { 0 };

		for (i = 0; i < files->items.nr; i++)
			if (files->selected[i])
				strvec_push(&args,
					    files->items.items[i].string);
		parse_pathspec(&ps_selected,
			       PATHSPEC_ALL_MAGIC & ~PATHSPEC_LITERAL,
			       PATHSPEC_LITERAL_PATH, "", args.v);
		res = run_add_p(s->r, ADD_P_ADD, NULL, &ps_selected);
		strvec_clear(&args);
		clear_pathspec(&ps_selected);
	}

	return res;
}

static int run_diff(struct add_i_state *s, const struct pathspec *ps,
		    struct prefix_item_list *files,
		    struct list_and_choose_options *opts)
{
	int res = 0;
	ssize_t count, i;

	struct object_id oid;
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &oid,
					     NULL);
	if (get_modified_files(s->r, INDEX_ONLY, files, ps, NULL, NULL) < 0)
		return -1;

	if (!files->items.nr) {
		putchar('\n');
		return 0;
	}

	opts->prompt = N_("Review diff");
	opts->flags = IMMEDIATE;
	count = list_and_choose(s, files, opts);
	opts->flags = 0;
	if (count > 0) {
		struct strvec args = STRVEC_INIT;

		strvec_pushl(&args, "git", "diff", "-p", "--cached",
			     oid_to_hex(!is_initial ? &oid :
					s->r->hash_algo->empty_tree),
			     "--", NULL);
		for (i = 0; i < files->items.nr; i++)
			if (files->selected[i])
				strvec_push(&args,
					    files->items.items[i].string);
		res = run_command_v_opt(args.v, 0);
		strvec_clear(&args);
	}

	putchar('\n');
	return res;
}

static int run_help(struct add_i_state *s, const struct pathspec *unused_ps,
		    struct prefix_item_list *unused_files,
		    struct list_and_choose_options *unused_opts)
{
	color_fprintf_ln(stdout, s->help_color, "status        - %s",
			 _("show paths with changes"));
	color_fprintf_ln(stdout, s->help_color, "update        - %s",
			 _("add working tree state to the staged set of changes"));
	color_fprintf_ln(stdout, s->help_color, "revert        - %s",
			 _("revert staged set of changes back to the HEAD version"));
	color_fprintf_ln(stdout, s->help_color, "patch         - %s",
			 _("pick hunks and update selectively"));
	color_fprintf_ln(stdout, s->help_color, "diff          - %s",
			 _("view diff between HEAD and index"));
	color_fprintf_ln(stdout, s->help_color, "add untracked - %s",
			 _("add contents of untracked files to the staged set of changes"));

	return 0;
}

static void choose_prompt_help(struct add_i_state *s)
{
	color_fprintf_ln(stdout, s->help_color, "%s",
			 _("Prompt help:"));
	color_fprintf_ln(stdout, s->help_color, "1          - %s",
			 _("select a single item"));
	color_fprintf_ln(stdout, s->help_color, "3-5        - %s",
			 _("select a range of items"));
	color_fprintf_ln(stdout, s->help_color, "2-3,6-9    - %s",
			 _("select multiple ranges"));
	color_fprintf_ln(stdout, s->help_color, "foo        - %s",
			 _("select item based on unique prefix"));
	color_fprintf_ln(stdout, s->help_color, "-...       - %s",
			 _("unselect specified items"));
	color_fprintf_ln(stdout, s->help_color, "*          - %s",
			 _("choose all items"));
	color_fprintf_ln(stdout, s->help_color, "           - %s",
			 _("(empty) finish selecting"));
}

typedef int (*command_t)(struct add_i_state *s, const struct pathspec *ps,
			 struct prefix_item_list *files,
			 struct list_and_choose_options *opts);

struct command_item {
	size_t prefix_length;
	command_t command;
};

struct print_command_item_data {
	const char *color, *reset;
};

static void print_command_item(int i, int selected,
			       struct string_list_item *item,
			       void *print_command_item_data)
{
	struct print_command_item_data *d = print_command_item_data;
	struct command_item *util = item->util;

	if (!util->prefix_length ||
	    !is_valid_prefix(item->string, util->prefix_length))
		printf(" %2d: %s", i + 1, item->string);
	else
		printf(" %2d: %s%.*s%s%s", i + 1,
		       d->color, (int)util->prefix_length, item->string,
		       d->reset, item->string + util->prefix_length);
}

static void command_prompt_help(struct add_i_state *s)
{
	const char *help_color = s->help_color;
	color_fprintf_ln(stdout, help_color, "%s", _("Prompt help:"));
	color_fprintf_ln(stdout, help_color, "1          - %s",
			 _("select a numbered item"));
	color_fprintf_ln(stdout, help_color, "foo        - %s",
			 _("select item based on unique prefix"));
	color_fprintf_ln(stdout, help_color, "           - %s",
			 _("(empty) select nothing"));
}

int run_add_i(struct repository *r, const struct pathspec *ps)
{
	struct add_i_state s = { NULL };
	struct print_command_item_data data = { "[", "]" };
	struct list_and_choose_options main_loop_opts = {
		{ 4, N_("*** Commands ***"), print_command_item, &data },
		N_("What now"), SINGLETON | IMMEDIATE, command_prompt_help
	};
	struct {
		const char *string;
		command_t command;
	} command_list[] = {
		{ "status", run_status },
		{ "update", run_update },
		{ "revert", run_revert },
		{ "add untracked", run_add_untracked },
		{ "patch", run_patch },
		{ "diff", run_diff },
		{ "quit", NULL },
		{ "help", run_help },
	};
	struct prefix_item_list commands = PREFIX_ITEM_LIST_INIT;

	struct print_file_item_data print_file_item_data = {
		"%12s %12s %s", NULL, NULL,
		STRBUF_INIT, STRBUF_INIT, STRBUF_INIT, STRBUF_INIT
	};
	struct list_and_choose_options opts = {
		{ 0, NULL, print_file_item, &print_file_item_data },
		NULL, 0, choose_prompt_help
	};
	struct strbuf header = STRBUF_INIT;
	struct prefix_item_list files = PREFIX_ITEM_LIST_INIT;
	ssize_t i;
	int res = 0;

	for (i = 0; i < ARRAY_SIZE(command_list); i++) {
		struct command_item *util = xcalloc(1, sizeof(*util));
		util->command = command_list[i].command;
		string_list_append(&commands.items, command_list[i].string)
			->util = util;
	}

	init_add_i_state(&s, r);

	/*
	 * When color was asked for, use the prompt color for
	 * highlighting, otherwise use square brackets.
	 */
	if (s.use_color) {
		data.color = s.prompt_color;
		data.reset = s.reset_color;
	}
	print_file_item_data.color = data.color;
	print_file_item_data.reset = data.reset;

	strbuf_addstr(&header, "     ");
	strbuf_addf(&header, print_file_item_data.modified_fmt,
		    _("staged"), _("unstaged"), _("path"));
	opts.list_opts.header = header.buf;

	if (discard_index(r->index) < 0 ||
	    repo_read_index(r) < 0 ||
	    repo_refresh_and_write_index(r, REFRESH_QUIET, 0, 1,
					 NULL, NULL, NULL) < 0)
		warning(_("could not refresh index"));

	res = run_status(&s, ps, &files, &opts);

	for (;;) {
		struct command_item *util;

		i = list_and_choose(&s, &commands, &main_loop_opts);
		if (i < 0 || i >= commands.items.nr)
			util = NULL;
		else
			util = commands.items.items[i].util;

		if (i == LIST_AND_CHOOSE_QUIT || (util && !util->command)) {
			printf(_("Bye.\n"));
			res = 0;
			break;
		}

		if (util)
			res = util->command(&s, ps, &files, &opts);
	}

	prefix_item_list_clear(&files);
	strbuf_release(&print_file_item_data.buf);
	strbuf_release(&print_file_item_data.name);
	strbuf_release(&print_file_item_data.index);
	strbuf_release(&print_file_item_data.worktree);
	strbuf_release(&header);
	prefix_item_list_clear(&commands);
	clear_add_i_state(&s);

	return res;
}
#include "cache.h"
#include "add-interactive.h"
#include "color.h"
#include "config.h"
#include "diffcore.h"
#include "revision.h"
#include "refs.h"
#include "string-list.h"
#include "lockfile.h"
#include "dir.h"
#include "run-command.h"
#include "prompt.h"

static void init_color(struct repository *r, struct add_i_state *s,
		       const char *section_and_slot, char *dst,
		       const char *default_color)
{
	char *key = xstrfmt("color.%s", section_and_slot);
	const char *value;

	if (!s->use_color)
		dst[0] = '\0';
	else if (repo_config_get_value(r, key, &value) ||
		 color_parse(value, dst))
		strlcpy(dst, default_color, COLOR_MAXLEN);

	free(key);
}

void init_add_i_state(struct add_i_state *s, struct repository *r)
{
	const char *value;

	s->r = r;

	if (repo_config_get_value(r, "color.interactive", &value))
		s->use_color = -1;
	else
		s->use_color =
			git_config_colorbool("color.interactive", value);
	s->use_color = want_color(s->use_color);

	init_color(r, s, "interactive.header", s->header_color, GIT_COLOR_BOLD);
	init_color(r, s, "interactive.help", s->help_color, GIT_COLOR_BOLD_RED);
	init_color(r, s, "interactive.prompt", s->prompt_color,
		   GIT_COLOR_BOLD_BLUE);
	init_color(r, s, "interactive.error", s->error_color,
		   GIT_COLOR_BOLD_RED);

	init_color(r, s, "diff.frag", s->fraginfo_color,
		   diff_get_color(s->use_color, DIFF_FRAGINFO));
	init_color(r, s, "diff.context", s->context_color, "fall back");
	if (!strcmp(s->context_color, "fall back"))
		init_color(r, s, "diff.plain", s->context_color,
			   diff_get_color(s->use_color, DIFF_CONTEXT));
	init_color(r, s, "diff.old", s->file_old_color,
		diff_get_color(s->use_color, DIFF_FILE_OLD));
	init_color(r, s, "diff.new", s->file_new_color,
		diff_get_color(s->use_color, DIFF_FILE_NEW));

	strlcpy(s->reset_color,
		s->use_color ? GIT_COLOR_RESET : "", COLOR_MAXLEN);

	FREE_AND_NULL(s->interactive_diff_filter);
	git_config_get_string("interactive.difffilter",
			      &s->interactive_diff_filter);

	FREE_AND_NULL(s->interactive_diff_algorithm);
	git_config_get_string("diff.algorithm",
			      &s->interactive_diff_algorithm);

	git_config_get_bool("interactive.singlekey", &s->use_single_key);
}

void clear_add_i_state(struct add_i_state *s)
{
	FREE_AND_NULL(s->interactive_diff_filter);
	FREE_AND_NULL(s->interactive_diff_algorithm);
	memset(s, 0, sizeof(*s));
	s->use_color = -1;
}

/*
 * A "prefix item list" is a list of items that are identified by a string, and
 * a unique prefix (if any) is determined for each item.
 *
 * It is implemented in the form of a pair of `string_list`s, the first one
 * duplicating the strings, with the `util` field pointing at a structure whose
 * first field must be `size_t prefix_length`.
 *
 * That `prefix_length` field will be computed by `find_unique_prefixes()`; It
 * will be set to zero if no valid, unique prefix could be found.
 *
 * The second `string_list` is called `sorted` and does _not_ duplicate the
 * strings but simply reuses the first one's, with the `util` field pointing at
 * the `string_item_list` of the first `string_list`. It  will be populated and
 * sorted by `find_unique_prefixes()`.
 */
struct prefix_item_list {
	struct string_list items;
	struct string_list sorted;
	int *selected; /* for multi-selections */
	size_t min_length, max_length;
};
#define PREFIX_ITEM_LIST_INIT \
	{ STRING_LIST_INIT_DUP, STRING_LIST_INIT_NODUP, NULL, 1, 4 }

static void prefix_item_list_clear(struct prefix_item_list *list)
{
	string_list_clear(&list->items, 1);
	string_list_clear(&list->sorted, 0);
	FREE_AND_NULL(list->selected);
}

static void extend_prefix_length(struct string_list_item *p,
				 const char *other_string, size_t max_length)
{
	size_t *len = p->util;

	if (!*len || memcmp(p->string, other_string, *len))
		return;

	for (;;) {
		char c = p->string[*len];

		/*
		 * Is `p` a strict prefix of `other`? Or have we exhausted the
		 * maximal length of the prefix? Or is the current character a
		 * multi-byte UTF-8 one? If so, there is no valid, unique
		 * prefix.
		 */
		if (!c || ++*len > max_length || !isascii(c)) {
			*len = 0;
			break;
		}

		if (c != other_string[*len - 1])
			break;
	}
}

static void find_unique_prefixes(struct prefix_item_list *list)
{
	size_t i;

	if (list->sorted.nr == list->items.nr)
		return;

	string_list_clear(&list->sorted, 0);
	/* Avoid reallocating incrementally */
	list->sorted.items = xmalloc(st_mult(sizeof(*list->sorted.items),
					     list->items.nr));
	list->sorted.nr = list->sorted.alloc = list->items.nr;

	for (i = 0; i < list->items.nr; i++) {
		list->sorted.items[i].string = list->items.items[i].string;
		list->sorted.items[i].util = list->items.items + i;
	}

	string_list_sort(&list->sorted);

	for (i = 0; i < list->sorted.nr; i++) {
		struct string_list_item *sorted_item = list->sorted.items + i;
		struct string_list_item *item = sorted_item->util;
		size_t *len = item->util;

		*len = 0;
		while (*len < list->min_length) {
			char c = item->string[(*len)++];

			if (!c || !isascii(c)) {
				*len = 0;
				break;
			}
		}

		if (i > 0)
			extend_prefix_length(item, sorted_item[-1].string,
					     list->max_length);
		if (i + 1 < list->sorted.nr)
			extend_prefix_length(item, sorted_item[1].string,
					     list->max_length);
	}
}

static ssize_t find_unique(const char *string, struct prefix_item_list *list)
{
	int index = string_list_find_insert_index(&list->sorted, string, 1);
	struct string_list_item *item;

	if (list->items.nr != list->sorted.nr)
		BUG("prefix_item_list in inconsistent state (%"PRIuMAX
		    " vs %"PRIuMAX")",
		    (uintmax_t)list->items.nr, (uintmax_t)list->sorted.nr);

	if (index < 0)
		item = list->sorted.items[-1 - index].util;
	else if (index > 0 &&
		 starts_with(list->sorted.items[index - 1].string, string))
		return -1;
	else if (index + 1 < list->sorted.nr &&
		 starts_with(list->sorted.items[index + 1].string, string))
		return -1;
	else if (index < list->sorted.nr &&
		 starts_with(list->sorted.items[index].string, string))
		item = list->sorted.items[index].util;
	else
		return -1;
	return item - list->items.items;
}

struct list_options {
	int columns;
	const char *header;
	void (*print_item)(int i, int selected, struct string_list_item *item,
			   void *print_item_data);
	void *print_item_data;
};

static void list(struct add_i_state *s, struct string_list *list, int *selected,
		 struct list_options *opts)
{
	int i, last_lf = 0;

	if (!list->nr)
		return;

	if (opts->header)
		color_fprintf_ln(stdout, s->header_color,
				 "%s", opts->header);

	for (i = 0; i < list->nr; i++) {
		opts->print_item(i, selected ? selected[i] : 0, list->items + i,
				 opts->print_item_data);

		if ((opts->columns) && ((i + 1) % (opts->columns))) {
			putchar('\t');
			last_lf = 0;
		}
		else {
			putchar('\n');
			last_lf = 1;
		}
	}

	if (!last_lf)
		putchar('\n');
}
struct list_and_choose_options {
	struct list_options list_opts;

	const char *prompt;
	enum {
		SINGLETON = (1<<0),
		IMMEDIATE = (1<<1),
	} flags;
	void (*print_help)(struct add_i_state *s);
};

#define LIST_AND_CHOOSE_ERROR (-1)
#define LIST_AND_CHOOSE_QUIT  (-2)

/*
 * Returns the selected index in singleton mode, the number of selected items
 * otherwise.
 *
 * If an error occurred, returns `LIST_AND_CHOOSE_ERROR`. Upon EOF,
 * `LIST_AND_CHOOSE_QUIT` is returned.
 */
static ssize_t list_and_choose(struct add_i_state *s,
			       struct prefix_item_list *items,
			       struct list_and_choose_options *opts)
{
	int singleton = opts->flags & SINGLETON;
	int immediate = opts->flags & IMMEDIATE;

	struct strbuf input = STRBUF_INIT;
	ssize_t res = singleton ? LIST_AND_CHOOSE_ERROR : 0;

	if (!singleton) {
		free(items->selected);
		CALLOC_ARRAY(items->selected, items->items.nr);
	}

	if (singleton && !immediate)
		BUG("singleton requires immediate");

	find_unique_prefixes(items);

	for (;;) {
		char *p;

		strbuf_reset(&input);

		list(s, &items->items, items->selected, &opts->list_opts);

		color_fprintf(stdout, s->prompt_color, "%s", opts->prompt);
		fputs(singleton ? "> " : ">> ", stdout);
		fflush(stdout);

		if (git_read_line_interactively(&input) == EOF) {
			putchar('\n');
			if (immediate)
				res = LIST_AND_CHOOSE_QUIT;
			break;
		}

		if (!input.len)
			break;

		if (!strcmp(input.buf, "?")) {
			opts->print_help(s);
			continue;
		}

		p = input.buf;
		for (;;) {
			size_t sep = strcspn(p, " \t\r\n,");
			int choose = 1;
			/* `from` is inclusive, `to` is exclusive */
			ssize_t from = -1, to = -1;

			if (!sep) {
				if (!*p)
					break;
				p++;
				continue;
			}

			/* Input that begins with '-'; de-select */
			if (*p == '-') {
				choose = 0;
				p++;
				sep--;
			}

			if (sep == 1 && *p == '*') {
				from = 0;
				to = items->items.nr;
			} else if (isdigit(*p)) {
				char *endp;
				/*
				 * A range can be specified like 5-7 or 5-.
				 *
				 * Note: `from` is 0-based while the user input
				 * is 1-based, hence we have to decrement by
				 * one. We do not have to decrement `to` even
				 * if it is 0-based because it is an exclusive
				 * boundary.
				 */
				from = strtoul(p, &endp, 10) - 1;
				if (endp == p + sep)
					to = from + 1;
				else if (*endp == '-') {
					if (isdigit(*(++endp)))
						to = strtoul(endp, &endp, 10);
					else
						to = items->items.nr;
					/* extra characters after the range? */
					if (endp != p + sep)
						from = -1;
				}
			}

			if (p[sep])
				p[sep++] = '\0';
			if (from < 0) {
				from = find_unique(p, items);
				if (from >= 0)
					to = from + 1;
			}

			if (from < 0 || from >= items->items.nr ||
			    (singleton && from + 1 != to)) {
				color_fprintf_ln(stderr, s->error_color,
						 _("Huh (%s)?"), p);
				break;
			} else if (singleton) {
				res = from;
				break;
			}

			if (to > items->items.nr)
				to = items->items.nr;

			for (; from < to; from++)
				if (items->selected[from] != choose) {
					items->selected[from] = choose;
					res += choose ? +1 : -1;
				}

			p += sep;
		}

		if ((immediate && res != LIST_AND_CHOOSE_ERROR) ||
		    !strcmp(input.buf, "*"))
			break;
	}

	strbuf_release(&input);
	return res;
}

struct adddel {
	uintmax_t add, del;
	unsigned seen:1, unmerged:1, binary:1;
};

struct file_item {
	size_t prefix_length;
	struct adddel index, worktree;
};

static void add_file_item(struct string_list *files, const char *name)
{
	struct file_item *item = xcalloc(1, sizeof(*item));

	string_list_append(files, name)->util = item;
}

struct pathname_entry {
	struct hashmap_entry ent;
	const char *name;
	struct file_item *item;
};

static int pathname_entry_cmp(const void *unused_cmp_data,
			      const struct hashmap_entry *he1,
			      const struct hashmap_entry *he2,
			      const void *name)
{
	const struct pathname_entry *e1 =
		container_of(he1, const struct pathname_entry, ent);
	const struct pathname_entry *e2 =
		container_of(he2, const struct pathname_entry, ent);

	return strcmp(e1->name, name ? (const char *)name : e2->name);
}

struct collection_status {
	enum { FROM_WORKTREE = 0, FROM_INDEX = 1 } mode;

	const char *reference;

	unsigned skip_unseen:1;
	size_t unmerged_count, binary_count;
	struct string_list *files;
	struct hashmap file_map;
};

static void collect_changes_cb(struct diff_queue_struct *q,
			       struct diff_options *options,
			       void *data)
{
	struct collection_status *s = data;
	struct diffstat_t stat = { 0 };
	int i;

	if (!q->nr)
		return;

	compute_diffstat(options, &stat, q);

	for (i = 0; i < stat.nr; i++) {
		const char *name = stat.files[i]->name;
		int hash = strhash(name);
		struct pathname_entry *entry;
		struct file_item *file_item;
		struct adddel *adddel, *other_adddel;

		entry = hashmap_get_entry_from_hash(&s->file_map, hash, name,
						    struct pathname_entry, ent);
		if (!entry) {
			if (s->skip_unseen)
				continue;

			add_file_item(s->files, name);

			entry = xcalloc(1, sizeof(*entry));
			hashmap_entry_init(&entry->ent, hash);
			entry->name = s->files->items[s->files->nr - 1].string;
			entry->item = s->files->items[s->files->nr - 1].util;
			hashmap_add(&s->file_map, &entry->ent);
		}

		file_item = entry->item;
		adddel = s->mode == FROM_INDEX ?
			&file_item->index : &file_item->worktree;
		other_adddel = s->mode == FROM_INDEX ?
			&file_item->worktree : &file_item->index;
		adddel->seen = 1;
		adddel->add = stat.files[i]->added;
		adddel->del = stat.files[i]->deleted;
		if (stat.files[i]->is_binary) {
			if (!other_adddel->binary)
				s->binary_count++;
			adddel->binary = 1;
		}
		if (stat.files[i]->is_unmerged) {
			if (!other_adddel->unmerged)
				s->unmerged_count++;
			adddel->unmerged = 1;
		}
	}
	free_diffstat_info(&stat);
}

enum modified_files_filter {
	NO_FILTER = 0,
	WORKTREE_ONLY = 1,
	INDEX_ONLY = 2,
};

static int get_modified_files(struct repository *r,
			      enum modified_files_filter filter,
			      struct prefix_item_list *files,
			      const struct pathspec *ps,
			      size_t *unmerged_count,
			      size_t *binary_count)
{
	struct object_id head_oid;
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING,
					     &head_oid, NULL);
	struct collection_status s = { 0 };
	int i;

	if (discard_index(r->index) < 0 ||
	    repo_read_index_preload(r, ps, 0) < 0)
		return error(_("could not read index"));

	prefix_item_list_clear(files);
	s.files = &files->items;
	hashmap_init(&s.file_map, pathname_entry_cmp, NULL, 0);

	for (i = 0; i < 2; i++) {
		struct rev_info rev;
		struct setup_revision_opt opt = { 0 };

		if (filter == INDEX_ONLY)
			s.mode = (i == 0) ? FROM_INDEX : FROM_WORKTREE;
		else
			s.mode = (i == 0) ? FROM_WORKTREE : FROM_INDEX;
		s.skip_unseen = filter && i;

		opt.def = is_initial ?
			empty_tree_oid_hex() : oid_to_hex(&head_oid);

		init_revisions(&rev, NULL);
		setup_revisions(0, NULL, &rev, &opt);

		rev.diffopt.output_format = DIFF_FORMAT_CALLBACK;
		rev.diffopt.format_callback = collect_changes_cb;
		rev.diffopt.format_callback_data = &s;

		if (ps)
			copy_pathspec(&rev.prune_data, ps);

		if (s.mode == FROM_INDEX)
			run_diff_index(&rev, 1);
		else {
			rev.diffopt.flags.ignore_dirty_submodules = 1;
			run_diff_files(&rev, 0);
		}

		if (ps)
			clear_pathspec(&rev.prune_data);
	}
	hashmap_clear_and_free(&s.file_map, struct pathname_entry, ent);
	if (unmerged_count)
		*unmerged_count = s.unmerged_count;
	if (binary_count)
		*binary_count = s.binary_count;

	/* While the diffs are ordered already, we ran *two* diffs... */
	string_list_sort(&files->items);

	return 0;
}

static void render_adddel(struct strbuf *buf,
				struct adddel *ad, const char *no_changes)
{
	if (ad->binary)
		strbuf_addstr(buf, _("binary"));
	else if (ad->seen)
		strbuf_addf(buf, "+%"PRIuMAX"/-%"PRIuMAX,
			    (uintmax_t)ad->add, (uintmax_t)ad->del);
	else
		strbuf_addstr(buf, no_changes);
}

/* filters out prefixes which have special meaning to list_and_choose() */
static int is_valid_prefix(const char *prefix, size_t prefix_len)
{
	return prefix_len && prefix &&
		/*
		 * We expect `prefix` to be NUL terminated, therefore this
		 * `strcspn()` call is okay, even if it might do much more
		 * work than strictly necessary.
		 */
		strcspn(prefix, " \t\r\n,") >= prefix_len &&	/* separators */
		*prefix != '-' &&				/* deselection */
		!isdigit(*prefix) &&				/* selection */
		(prefix_len != 1 ||
		 (*prefix != '*' &&				/* "all" wildcard */
		  *prefix != '?'));				/* prompt help */
}

struct print_file_item_data {
	const char *modified_fmt, *color, *reset;
	struct strbuf buf, name, index, worktree;
	unsigned only_names:1;
};

static void print_file_item(int i, int selected, struct string_list_item *item,
			    void *print_file_item_data)
{
	struct file_item *c = item->util;
	struct print_file_item_data *d = print_file_item_data;
	const char *highlighted = NULL;

	strbuf_reset(&d->index);
	strbuf_reset(&d->worktree);
	strbuf_reset(&d->buf);

	/* Format the item with the prefix highlighted. */
	if (c->prefix_length > 0 &&
	    is_valid_prefix(item->string, c->prefix_length)) {
		strbuf_reset(&d->name);
		strbuf_addf(&d->name, "%s%.*s%s%s", d->color,
			    (int)c->prefix_length, item->string, d->reset,
			    item->string + c->prefix_length);
		highlighted = d->name.buf;
	}

	if (d->only_names) {
		printf("%c%2d: %s", selected ? '*' : ' ', i + 1,
		       highlighted ? highlighted : item->string);
		return;
	}

	render_adddel(&d->worktree, &c->worktree, _("nothing"));
	render_adddel(&d->index, &c->index, _("unchanged"));

	strbuf_addf(&d->buf, d->modified_fmt, d->index.buf, d->worktree.buf,
		    highlighted ? highlighted : item->string);

	printf("%c%2d: %s", selected ? '*' : ' ', i + 1, d->buf.buf);
}

static int run_status(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	if (get_modified_files(s->r, NO_FILTER, files, ps, NULL, NULL) < 0)
		return -1;

	list(s, &files->items, NULL, &opts->list_opts);
	putchar('\n');

	return 0;
}

static int run_update(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	int res = 0, fd;
	size_t count, i;
	struct lock_file index_lock;

	if (get_modified_files(s->r, WORKTREE_ONLY, files, ps, NULL, NULL) < 0)
		return -1;

	if (!files->items.nr) {
		putchar('\n');
		return 0;
	}

	opts->prompt = N_("Update");
	count = list_and_choose(s, files, opts);
	if (count <= 0) {
		putchar('\n');
		return 0;
	}

	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	if (fd < 0) {
		putchar('\n');
		return -1;
	}

	for (i = 0; i < files->items.nr; i++) {
		const char *name = files->items.items[i].string;
		if (files->selected[i] &&
		    add_file_to_index(s->r->index, name, 0) < 0) {
			res = error(_("could not stage '%s'"), name);
			break;
		}
	}

	if (!res && write_locked_index(s->r->index, &index_lock, COMMIT_LOCK) < 0)
		res = error(_("could not write index"));

	if (!res)
		printf(Q_("updated %d path\n",
			  "updated %d paths\n", count), (int)count);

	putchar('\n');
	return res;
}

static void revert_from_diff(struct diff_queue_struct *q,
			     struct diff_options *opt, void *data)
{
	int i, add_flags = ADD_CACHE_OK_TO_ADD | ADD_CACHE_OK_TO_REPLACE;

	for (i = 0; i < q->nr; i++) {
		struct diff_filespec *one = q->queue[i]->one;
		struct cache_entry *ce;

		if (!(one->mode && !is_null_oid(&one->oid))) {
			remove_file_from_index(opt->repo->index, one->path);
			printf(_("note: %s is untracked now.\n"), one->path);
		} else {
			ce = make_cache_entry(opt->repo->index, one->mode,
					      &one->oid, one->path, 0, 0);
			if (!ce)
				die(_("make_cache_entry failed for path '%s'"),
				    one->path);
			add_index_entry(opt->repo->index, ce, add_flags);
		}
	}
}

static int run_revert(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	int res = 0, fd;
	size_t count, i, j;

	struct object_id oid;
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &oid,
					     NULL);
	struct lock_file index_lock;
	const char **paths;
	struct tree *tree;
	struct diff_options diffopt = { NULL };

	if (get_modified_files(s->r, INDEX_ONLY, files, ps, NULL, NULL) < 0)
		return -1;

	if (!files->items.nr) {
		putchar('\n');
		return 0;
	}

	opts->prompt = N_("Revert");
	count = list_and_choose(s, files, opts);
	if (count <= 0)
		goto finish_revert;

	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	if (fd < 0) {
		res = -1;
		goto finish_revert;
	}

	if (is_initial)
		oidcpy(&oid, s->r->hash_algo->empty_tree);
	else {
		tree = parse_tree_indirect(&oid);
		if (!tree) {
			res = error(_("Could not parse HEAD^{tree}"));
			goto finish_revert;
		}
		oidcpy(&oid, &tree->object.oid);
	}

	ALLOC_ARRAY(paths, count + 1);
	for (i = j = 0; i < files->items.nr; i++)
		if (files->selected[i])
			paths[j++] = files->items.items[i].string;
	paths[j] = NULL;

	parse_pathspec(&diffopt.pathspec, 0,
		       PATHSPEC_PREFER_FULL | PATHSPEC_LITERAL_PATH,
		       NULL, paths);

	diffopt.output_format = DIFF_FORMAT_CALLBACK;
	diffopt.format_callback = revert_from_diff;
	diffopt.flags.override_submodule_config = 1;
	diffopt.repo = s->r;

	if (do_diff_cache(&oid, &diffopt))
		res = -1;
	else {
		diffcore_std(&diffopt);
		diff_flush(&diffopt);
	}
	free(paths);
	clear_pathspec(&diffopt.pathspec);

	if (!res && write_locked_index(s->r->index, &index_lock,
				       COMMIT_LOCK) < 0)
		res = -1;
	else
		res = repo_refresh_and_write_index(s->r, REFRESH_QUIET, 0, 1,
						   NULL, NULL, NULL);

	if (!res)
		printf(Q_("reverted %d path\n",
			  "reverted %d paths\n", count), (int)count);

finish_revert:
	putchar('\n');
	return res;
}

static int get_untracked_files(struct repository *r,
			       struct prefix_item_list *files,
			       const struct pathspec *ps)
{
	struct dir_struct dir = { 0 };
	size_t i;
	struct strbuf buf = STRBUF_INIT;

	if (repo_read_index(r) < 0)
		return error(_("could not read index"));

	prefix_item_list_clear(files);
	setup_standard_excludes(&dir);
	add_pattern_list(&dir, EXC_CMDL, "--exclude option");
	fill_directory(&dir, r->index, ps);

	for (i = 0; i < dir.nr; i++) {
		struct dir_entry *ent = dir.entries[i];

		if (index_name_is_other(r->index, ent->name, ent->len)) {
			strbuf_reset(&buf);
			strbuf_add(&buf, ent->name, ent->len);
			add_file_item(&files->items, buf.buf);
		}
	}

	strbuf_release(&buf);
	return 0;
}

static int run_add_untracked(struct add_i_state *s, const struct pathspec *ps,
		      struct prefix_item_list *files,
		      struct list_and_choose_options *opts)
{
	struct print_file_item_data *d = opts->list_opts.print_item_data;
	int res = 0, fd;
	size_t count, i;
	struct lock_file index_lock;

	if (get_untracked_files(s->r, files, ps) < 0)
		return -1;

	if (!files->items.nr) {
		printf(_("No untracked files.\n"));
		goto finish_add_untracked;
	}

	opts->prompt = N_("Add untracked");
	d->only_names = 1;
	count = list_and_choose(s, files, opts);
	d->only_names = 0;
	if (count <= 0)
		goto finish_add_untracked;

	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	if (fd < 0) {
		res = -1;
		goto finish_add_untracked;
	}

	for (i = 0; i < files->items.nr; i++) {
		const char *name = files->items.items[i].string;
		if (files->selected[i] &&
		    add_file_to_index(s->r->index, name, 0) < 0) {
			res = error(_("could not stage '%s'"), name);
			break;
		}
	}

	if (!res &&
	    write_locked_index(s->r->index, &index_lock, COMMIT_LOCK) < 0)
		res = error(_("could not write index"));

	if (!res)
		printf(Q_("added %d path\n",
			  "added %d paths\n", count), (int)count);

finish_add_untracked:
	putchar('\n');
	return res;
}

static int run_patch(struct add_i_state *s, const struct pathspec *ps,
		     struct prefix_item_list *files,
		     struct list_and_choose_options *opts)
{
	int res = 0;
	ssize_t count, i, j;
	size_t unmerged_count = 0, binary_count = 0;

	if (get_modified_files(s->r, WORKTREE_ONLY, files, ps,
			       &unmerged_count, &binary_count) < 0)
		return -1;

	if (unmerged_count || binary_count) {
		for (i = j = 0; i < files->items.nr; i++) {
			struct file_item *item = files->items.items[i].util;

			if (item->index.binary || item->worktree.binary) {
				free(item);
				free(files->items.items[i].string);
			} else if (item->index.unmerged ||
				 item->worktree.unmerged) {
				color_fprintf_ln(stderr, s->error_color,
						 _("ignoring unmerged: %s"),
						 files->items.items[i].string);
				free(item);
				free(files->items.items[i].string);
			} else
				files->items.items[j++] = files->items.items[i];
		}
		files->items.nr = j;
	}

	if (!files->items.nr) {
		if (binary_count)
			fprintf(stderr, _("Only binary files changed.\n"));
		else
			fprintf(stderr, _("No changes.\n"));
		return 0;
	}

	opts->prompt = N_("Patch update");
	count = list_and_choose(s, files, opts);
	if (count > 0) {
		struct strvec args = STRVEC_INIT;
		struct pathspec ps_selected = { 0 };

		for (i = 0; i < files->items.nr; i++)
			if (files->selected[i])
				strvec_push(&args,
					    files->items.items[i].string);
		parse_pathspec(&ps_selected,
			       PATHSPEC_ALL_MAGIC & ~PATHSPEC_LITERAL,
			       PATHSPEC_LITERAL_PATH, "", args.v);
		res = run_add_p(s->r, ADD_P_ADD, NULL, &ps_selected);
		strvec_clear(&args);
		clear_pathspec(&ps_selected);
	}

	return res;
}

static int run_diff(struct add_i_state *s, const struct pathspec *ps,
		    struct prefix_item_list *files,
		    struct list_and_choose_options *opts)
{
	int res = 0;
	ssize_t count, i;

	struct object_id oid;
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &oid,
					     NULL);
	if (get_modified_files(s->r, INDEX_ONLY, files, ps, NULL, NULL) < 0)
		return -1;

	if (!files->items.nr) {
		putchar('\n');
		return 0;
	}

	opts->prompt = N_("Review diff");
	opts->flags = IMMEDIATE;
	count = list_and_choose(s, files, opts);
	opts->flags = 0;
	if (count > 0) {
		struct strvec args = STRVEC_INIT;

		strvec_pushl(&args, "git", "diff", "-p", "--cached",
			     oid_to_hex(!is_initial ? &oid :
					s->r->hash_algo->empty_tree),
			     "--", NULL);
		for (i = 0; i < files->items.nr; i++)
			if (files->selected[i])
				strvec_push(&args,
					    files->items.items[i].string);
		res = run_command_v_opt(args.v, 0);
		strvec_clear(&args);
	}

	putchar('\n');
	return res;
}

static int run_help(struct add_i_state *s, const struct pathspec *unused_ps,
		    struct prefix_item_list *unused_files,
		    struct list_and_choose_options *unused_opts)
{
	color_fprintf_ln(stdout, s->help_color, "status        - %s",
			 _("show paths with changes"));
	color_fprintf_ln(stdout, s->help_color, "update        - %s",
			 _("add working tree state to the staged set of changes"));
	color_fprintf_ln(stdout, s->help_color, "revert        - %s",
			 _("revert staged set of changes back to the HEAD version"));
	color_fprintf_ln(stdout, s->help_color, "patch         - %s",
			 _("pick hunks and update selectively"));
	color_fprintf_ln(stdout, s->help_color, "diff          - %s",
			 _("view diff between HEAD and index"));
	color_fprintf_ln(stdout, s->help_color, "add untracked - %s",
			 _("add contents of untracked files to the staged set of changes"));

	return 0;
}

static void choose_prompt_help(struct add_i_state *s)
{
	color_fprintf_ln(stdout, s->help_color, "%s",
			 _("Prompt help:"));
	color_fprintf_ln(stdout, s->help_color, "1          - %s",
			 _("select a single item"));
	color_fprintf_ln(stdout, s->help_color, "3-5        - %s",
			 _("select a range of items"));
	color_fprintf_ln(stdout, s->help_color, "2-3,6-9    - %s",
			 _("select multiple ranges"));
	color_fprintf_ln(stdout, s->help_color, "foo        - %s",
			 _("select item based on unique prefix"));
	color_fprintf_ln(stdout, s->help_color, "-...       - %s",
			 _("unselect specified items"));
	color_fprintf_ln(stdout, s->help_color, "*          - %s",
			 _("choose all items"));
	color_fprintf_ln(stdout, s->help_color, "           - %s",
			 _("(empty) finish selecting"));
}

typedef int (*command_t)(struct add_i_state *s, const struct pathspec *ps,
			 struct prefix_item_list *files,
			 struct list_and_choose_options *opts);

struct command_item {
	size_t prefix_length;
	command_t command;
};

struct print_command_item_data {
	const char *color, *reset;
};

static void print_command_item(int i, int selected,
			       struct string_list_item *item,
			       void *print_command_item_data)
{
	struct print_command_item_data *d = print_command_item_data;
	struct command_item *util = item->util;

	if (!util->prefix_length ||
	    !is_valid_prefix(item->string, util->prefix_length))
		printf(" %2d: %s", i + 1, item->string);
	else
		printf(" %2d: %s%.*s%s%s", i + 1,
		       d->color, (int)util->prefix_length, item->string,
		       d->reset, item->string + util->prefix_length);
}

static void command_prompt_help(struct add_i_state *s)
{
	const char *help_color = s->help_color;
	color_fprintf_ln(stdout, help_color, "%s", _("Prompt help:"));
	color_fprintf_ln(stdout, help_color, "1          - %s",
			 _("select a numbered item"));
	color_fprintf_ln(stdout, help_color, "foo        - %s",
			 _("select item based on unique prefix"));
	color_fprintf_ln(stdout, help_color, "           - %s",
			 _("(empty) select nothing"));
}

int run_add_i(struct repository *r, const struct pathspec *ps)
{
	struct add_i_state s = { NULL };
	struct print_command_item_data data = { "[", "]" };
	struct list_and_choose_options main_loop_opts = {
		{ 4, N_("*** Commands ***"), print_command_item, &data },
		N_("What now"), SINGLETON | IMMEDIATE, command_prompt_help
	};
	struct {
		const char *string;
		command_t command;
	} command_list[] = {
		{ "status", run_status },
		{ "update", run_update },
		{ "revert", run_revert },
		{ "add untracked", run_add_untracked },
		{ "patch", run_patch },
		{ "diff", run_diff },
		{ "quit", NULL },
		{ "help", run_help },
	};
	struct prefix_item_list commands = PREFIX_ITEM_LIST_INIT;

	struct print_file_item_data print_file_item_data = {
		"%12s %12s %s", NULL, NULL,
		STRBUF_INIT, STRBUF_INIT, STRBUF_INIT, STRBUF_INIT
	};
	struct list_and_choose_options opts = {
		{ 0, NULL, print_file_item, &print_file_item_data },
		NULL, 0, choose_prompt_help
	};
	struct strbuf header = STRBUF_INIT;
	struct prefix_item_list files = PREFIX_ITEM_LIST_INIT;
	ssize_t i;
	int res = 0;

	for (i = 0; i < ARRAY_SIZE(command_list); i++) {
		struct command_item *util = xcalloc(1, sizeof(*util));
		util->command = command_list[i].command;
		string_list_append(&commands.items, command_list[i].string)
			->util = util;
	}

	init_add_i_state(&s, r);

	/*
	 * When color was asked for, use the prompt color for
	 * highlighting, otherwise use square brackets.
	 */
	if (s.use_color) {
		data.color = s.prompt_color;
		data.reset = s.reset_color;
	}
	print_file_item_data.color = data.color;
	print_file_item_data.reset = data.reset;

	strbuf_addstr(&header, "     ");
	strbuf_addf(&header, print_file_item_data.modified_fmt,
		    _("staged"), _("unstaged"), _("path"));
	opts.list_opts.header = header.buf;

	if (discard_index(r->index) < 0 ||
	    repo_read_index(r) < 0 ||
	    repo_refresh_and_write_index(r, REFRESH_QUIET, 0, 1,
					 NULL, NULL, NULL) < 0)
		warning(_("could not refresh index"));

	res = run_status(&s, ps, &files, &opts);

	for (;;) {
		struct command_item *util;

		i = list_and_choose(&s, &commands, &main_loop_opts);
		if (i < 0 || i >= commands.items.nr)
			util = NULL;
		else
			util = commands.items.items[i].util;

		if (i == LIST_AND_CHOOSE_QUIT || (util && !util->command)) {
			printf(_("Bye.\n"));
			res = 0;
			break;
		}

		if (util)
			res = util->command(&s, ps, &files, &opts);
	}

	prefix_item_list_clear(&files);
	strbuf_release(&print_file_item_data.buf);
	strbuf_release(&print_file_item_data.name);
	strbuf_release(&print_file_item_data.index);
	strbuf_release(&print_file_item_data.worktree);
	strbuf_release(&header);
	prefix_item_list_clear(&commands);
	clear_add_i_state(&s);

	return res;
}
#include "cache.h"
#include "config.h"
#include "builtin.h"
#include "exec-cmd.h"
#include "run-command.h"
#include "levenshtein.h"
#include "help.h"
#include "command-list.h"
#include "string-list.h"
#include "column.h"
#include "version.h"
#include "refs.h"
#include "parse-options.h"

struct category_description {
	uint32_t category;
	const char *desc;
};
static uint32_t common_mask =
	CAT_init | CAT_worktree | CAT_info |
	CAT_history | CAT_remote;
static struct category_description common_categories[] = {
	{ CAT_init, N_("start a working area (see also: git help tutorial)") },
	{ CAT_worktree, N_("work on the current change (see also: git help everyday)") },
	{ CAT_info, N_("examine the history and state (see also: git help revisions)") },
	{ CAT_history, N_("grow, mark and tweak your common history") },
	{ CAT_remote, N_("collaborate (see also: git help workflows)") },
	{ 0, NULL }
};
static struct category_description main_categories[] = {
	{ CAT_mainporcelain, N_("Main Porcelain Commands") },
	{ CAT_ancillarymanipulators, N_("Ancillary Commands / Manipulators") },
	{ CAT_ancillaryinterrogators, N_("Ancillary Commands / Interrogators") },
	{ CAT_foreignscminterface, N_("Interacting with Others") },
	{ CAT_plumbingmanipulators, N_("Low-level Commands / Manipulators") },
	{ CAT_plumbinginterrogators, N_("Low-level Commands / Interrogators") },
	{ CAT_synchingrepositories, N_("Low-level Commands / Syncing Repositories") },

	{ 0, NULL }
};

static const char *drop_prefix(const char *name, uint32_t category)
{
	const char *new_name;

	if (skip_prefix(name, "git-", &new_name))
		return new_name;
	if (category == CAT_guide && skip_prefix(name, "git", &new_name))
		return new_name;
	return name;

}

static void extract_cmds(struct cmdname_help **p_cmds, uint32_t mask)
{
	int i, nr = 0;
	struct cmdname_help *cmds;

	if (ARRAY_SIZE(command_list) == 0)
		BUG("empty command_list[] is a sign of broken generate-cmdlist.sh");

	ALLOC_ARRAY(cmds, ARRAY_SIZE(command_list) + 1);

	for (i = 0; i < ARRAY_SIZE(command_list); i++) {
		const struct cmdname_help *cmd = command_list + i;

		if (!(cmd->category & mask))
			continue;

		cmds[nr] = *cmd;
		cmds[nr].name = drop_prefix(cmd->name, cmd->category);

		nr++;
	}
	cmds[nr].name = NULL;
	*p_cmds = cmds;
}

static void print_command_list(const struct cmdname_help *cmds,
			       uint32_t mask, int longest)
{
	int i;

	for (i = 0; cmds[i].name; i++) {
		if (cmds[i].category & mask) {
			size_t len = strlen(cmds[i].name);
			printf("   %s   ", cmds[i].name);
			if (longest > len)
				mput_char(' ', longest - len);
			puts(_(cmds[i].help));
		}
	}
}

static int cmd_name_cmp(const void *elem1, const void *elem2)
{
	const struct cmdname_help *e1 = elem1;
	const struct cmdname_help *e2 = elem2;

	return strcmp(e1->name, e2->name);
}

static void print_cmd_by_category(const struct category_description *catdesc,
				  int *longest_p)
{
	struct cmdname_help *cmds;
	int longest = 0;
	int i, nr = 0;
	uint32_t mask = 0;

	for (i = 0; catdesc[i].desc; i++)
		mask |= catdesc[i].category;

	extract_cmds(&cmds, mask);

	for (i = 0; cmds[i].name; i++, nr++) {
		if (longest < strlen(cmds[i].name))
			longest = strlen(cmds[i].name);
	}
	QSORT(cmds, nr, cmd_name_cmp);

	for (i = 0; catdesc[i].desc; i++) {
		uint32_t mask = catdesc[i].category;
		const char *desc = catdesc[i].desc;

		printf("\n%s\n", _(desc));
		print_command_list(cmds, mask, longest);
	}
	free(cmds);
	if (longest_p)
		*longest_p = longest;
}

void add_cmdname(struct cmdnames *cmds, const char *name, int len)
{
	struct cmdname *ent;
	FLEX_ALLOC_MEM(ent, name, name, len);
	ent->len = len;

	ALLOC_GROW(cmds->names, cmds->cnt + 1, cmds->alloc);
	cmds->names[cmds->cnt++] = ent;
}

static void clean_cmdnames(struct cmdnames *cmds)
{
	int i;
	for (i = 0; i < cmds->cnt; ++i)
		free(cmds->names[i]);
	free(cmds->names);
	cmds->cnt = 0;
	cmds->alloc = 0;
}

static int cmdname_compare(const void *a_, const void *b_)
{
	struct cmdname *a = *(struct cmdname **)a_;
	struct cmdname *b = *(struct cmdname **)b_;
	return strcmp(a->name, b->name);
}

static void uniq(struct cmdnames *cmds)
{
	int i, j;

	if (!cmds->cnt)
		return;

	for (i = j = 1; i < cmds->cnt; i++) {
		if (!strcmp(cmds->names[i]->name, cmds->names[j-1]->name))
			free(cmds->names[i]);
		else
			cmds->names[j++] = cmds->names[i];
	}

	cmds->cnt = j;
}

void exclude_cmds(struct cmdnames *cmds, struct cmdnames *excludes)
{
	int ci, cj, ei;
	int cmp;

	ci = cj = ei = 0;
	while (ci < cmds->cnt && ei < excludes->cnt) {
		cmp = strcmp(cmds->names[ci]->name, excludes->names[ei]->name);
		if (cmp < 0)
			cmds->names[cj++] = cmds->names[ci++];
		else if (cmp == 0) {
			ei++;
			free(cmds->names[ci++]);
		} else if (cmp > 0)
			ei++;
	}

	while (ci < cmds->cnt)
		cmds->names[cj++] = cmds->names[ci++];

	cmds->cnt = cj;
}

static void pretty_print_cmdnames(struct cmdnames *cmds, unsigned int colopts)
{
	struct string_list list = STRING_LIST_INIT_NODUP;
	struct column_options copts;
	int i;

	for (i = 0; i < cmds->cnt; i++)
		string_list_append(&list, cmds->names[i]->name);
	/*
	 * always enable column display, we only consult column.*
	 * about layout strategy and stuff
	 */
	colopts = (colopts & ~COL_ENABLE_MASK) | COL_ENABLED;
	memset(&copts, 0, sizeof(copts));
	copts.indent = "  ";
	copts.padding = 2;
	print_columns(&list, colopts, &copts);
	string_list_clear(&list, 0);
}

static void list_commands_in_dir(struct cmdnames *cmds,
					 const char *path,
					 const char *prefix)
{
	DIR *dir = opendir(path);
	struct dirent *de;
	struct strbuf buf = STRBUF_INIT;
	int len;

	if (!dir)
		return;
	if (!prefix)
		prefix = "git-";

	strbuf_addf(&buf, "%s/", path);
	len = buf.len;

	while ((de = readdir(dir)) != NULL) {
		const char *ent;
		size_t entlen;

		if (!skip_prefix(de->d_name, prefix, &ent))
			continue;

		strbuf_setlen(&buf, len);
		strbuf_addstr(&buf, de->d_name);
		if (!is_executable(buf.buf))
			continue;

		entlen = strlen(ent);
		strip_suffix(ent, ".exe", &entlen);

		add_cmdname(cmds, ent, entlen);
	}
	closedir(dir);
	strbuf_release(&buf);
}

void load_command_list(const char *prefix,
		struct cmdnames *main_cmds,
		struct cmdnames *other_cmds)
{
	const char *env_path = getenv("PATH");
	const char *exec_path = git_exec_path();

	if (exec_path) {
		list_commands_in_dir(main_cmds, exec_path, prefix);
		QSORT(main_cmds->names, main_cmds->cnt, cmdname_compare);
		uniq(main_cmds);
	}

	if (env_path) {
		char *paths, *path, *colon;
		path = paths = xstrdup(env_path);
		while (1) {
			if ((colon = strchr(path, PATH_SEP)))
				*colon = 0;
			if (!exec_path || strcmp(path, exec_path))
				list_commands_in_dir(other_cmds, path, prefix);

			if (!colon)
				break;
			path = colon + 1;
		}
		free(paths);

		QSORT(other_cmds->names, other_cmds->cnt, cmdname_compare);
		uniq(other_cmds);
	}
	exclude_cmds(other_cmds, main_cmds);
}

void list_commands(unsigned int colopts,
		   struct cmdnames *main_cmds, struct cmdnames *other_cmds)
{
	if (main_cmds->cnt) {
		const char *exec_path = git_exec_path();
		printf_ln(_("available git commands in '%s'"), exec_path);
		putchar('\n');
		pretty_print_cmdnames(main_cmds, colopts);
		putchar('\n');
	}

	if (other_cmds->cnt) {
		printf_ln(_("git commands available from elsewhere on your $PATH"));
		putchar('\n');
		pretty_print_cmdnames(other_cmds, colopts);
		putchar('\n');
	}
}

void list_common_cmds_help(void)
{
	puts(_("These are common Git commands used in various situations:"));
	print_cmd_by_category(common_categories, NULL);
}

void list_all_main_cmds(struct string_list *list)
{
	struct cmdnames main_cmds, other_cmds;
	int i;

	memset(&main_cmds, 0, sizeof(main_cmds));
	memset(&other_cmds, 0, sizeof(other_cmds));
	load_command_list("git-", &main_cmds, &other_cmds);

	for (i = 0; i < main_cmds.cnt; i++)
		string_list_append(list, main_cmds.names[i]->name);

	clean_cmdnames(&main_cmds);
	clean_cmdnames(&other_cmds);
}

void list_all_other_cmds(struct string_list *list)
{
	struct cmdnames main_cmds, other_cmds;
	int i;

	memset(&main_cmds, 0, sizeof(main_cmds));
	memset(&other_cmds, 0, sizeof(other_cmds));
	load_command_list("git-", &main_cmds, &other_cmds);

	for (i = 0; i < other_cmds.cnt; i++)
		string_list_append(list, other_cmds.names[i]->name);

	clean_cmdnames(&main_cmds);
	clean_cmdnames(&other_cmds);
}

void list_cmds_by_category(struct string_list *list,
			   const char *cat)
{
	int i, n = ARRAY_SIZE(command_list);
	uint32_t cat_id = 0;

	for (i = 0; category_names[i]; i++) {
		if (!strcmp(cat, category_names[i])) {
			cat_id = 1UL << i;
			break;
		}
	}
	if (!cat_id)
		die(_("unsupported command listing type '%s'"), cat);

	for (i = 0; i < n; i++) {
		struct cmdname_help *cmd = command_list + i;

		if (!(cmd->category & cat_id))
			continue;
		string_list_append(list, drop_prefix(cmd->name, cmd->category));
	}
}

void list_cmds_by_config(struct string_list *list)
{
	const char *cmd_list;

	if (git_config_get_string_const("completion.commands", &cmd_list))
		return;

	string_list_sort(list);
	string_list_remove_duplicates(list, 0);

	while (*cmd_list) {
		struct strbuf sb = STRBUF_INIT;
		const char *p = strchrnul(cmd_list, ' ');

		strbuf_add(&sb, cmd_list, p - cmd_list);
		if (sb.buf[0] == '-')
			string_list_remove(list, sb.buf + 1, 0);
		else
			string_list_insert(list, sb.buf);
		strbuf_release(&sb);
		while (*p == ' ')
			p++;
		cmd_list = p;
	}
}

void list_common_guides_help(void)
{
	struct category_description catdesc[] = {
		{ CAT_guide, N_("The common Git guides are:") },
		{ 0, NULL }
	};
	print_cmd_by_category(catdesc, NULL);
	putchar('\n');
}

struct slot_expansion {
	const char *prefix;
	const char *placeholder;
	void (*fn)(struct string_list *list, const char *prefix);
	int found;
};

void list_config_help(int for_human)
{
	struct slot_expansion slot_expansions[] = {
		{ "advice", "*", list_config_advices },
		{ "color.branch", "<slot>", list_config_color_branch_slots },
		{ "color.decorate", "<slot>", list_config_color_decorate_slots },
		{ "color.diff", "<slot>", list_config_color_diff_slots },
		{ "color.grep", "<slot>", list_config_color_grep_slots },
		{ "color.interactive", "<slot>", list_config_color_interactive_slots },
		{ "color.remote", "<slot>", list_config_color_sideband_slots },
		{ "color.status", "<slot>", list_config_color_status_slots },
		{ "fsck", "<msg-id>", list_config_fsck_msg_ids },
		{ "receive.fsck", "<msg-id>", list_config_fsck_msg_ids },
		{ NULL, NULL, NULL }
	};
	const char **p;
	struct slot_expansion *e;
	struct string_list keys = STRING_LIST_INIT_DUP;
	int i;

	for (p = config_name_list; *p; p++) {
		const char *var = *p;
		struct strbuf sb = STRBUF_INIT;

		for (e = slot_expansions; e->prefix; e++) {

			strbuf_reset(&sb);
			strbuf_addf(&sb, "%s.%s", e->prefix, e->placeholder);
			if (!strcasecmp(var, sb.buf)) {
				e->fn(&keys, e->prefix);
				e->found++;
				break;
			}
		}
		strbuf_release(&sb);
		if (!e->prefix)
			string_list_append(&keys, var);
	}

	for (e = slot_expansions; e->prefix; e++)
		if (!e->found)
			BUG("slot_expansion %s.%s is not used",
			    e->prefix, e->placeholder);

	string_list_sort(&keys);
	for (i = 0; i < keys.nr; i++) {
		const char *var = keys.items[i].string;
		const char *wildcard, *tag, *cut;

		if (for_human) {
			puts(var);
			continue;
		}

		wildcard = strchr(var, '*');
		tag = strchr(var, '<');

		if (!wildcard && !tag) {
			puts(var);
			continue;
		}

		if (wildcard && !tag)
			cut = wildcard;
		else if (!wildcard && tag)
			cut = tag;
		else
			cut = wildcard < tag ? wildcard : tag;

		/*
		 * We may produce duplicates, but that's up to
		 * git-completion.bash to handle
		 */
		printf("%.*s\n", (int)(cut - var), var);
	}
	string_list_clear(&keys, 0);
}

static int get_alias(const char *var, const char *value, void *data)
{
	struct string_list *list = data;

	if (skip_prefix(var, "alias.", &var))
		string_list_append(list, var)->util = xstrdup(value);

	return 0;
}

void list_all_cmds_help(void)
{
	struct string_list others = STRING_LIST_INIT_DUP;
	struct string_list alias_list = STRING_LIST_INIT_DUP;
	struct cmdname_help *aliases;
	int i, longest;

	printf_ln(_("See 'git help <command>' to read about a specific subcommand"));
	print_cmd_by_category(main_categories, &longest);

	list_all_other_cmds(&others);
	if (others.nr)
		printf("\n%s\n", _("External commands"));
	for (i = 0; i < others.nr; i++)
		printf("   %s\n", others.items[i].string);
	string_list_clear(&others, 0);

	git_config(get_alias, &alias_list);
	string_list_sort(&alias_list);

	for (i = 0; i < alias_list.nr; i++) {
		size_t len = strlen(alias_list.items[i].string);
		if (longest < len)
			longest = len;
	}

	if (alias_list.nr) {
		printf("\n%s\n", _("Command aliases"));
		ALLOC_ARRAY(aliases, alias_list.nr + 1);
		for (i = 0; i < alias_list.nr; i++) {
			aliases[i].name = alias_list.items[i].string;
			aliases[i].help = alias_list.items[i].util;
			aliases[i].category = 1;
		}
		aliases[alias_list.nr].name = NULL;
		print_command_list(aliases, 1, longest);
		free(aliases);
	}
	string_list_clear(&alias_list, 1);
}

int is_in_cmdlist(struct cmdnames *c, const char *s)
{
	int i;
	for (i = 0; i < c->cnt; i++)
		if (!strcmp(s, c->names[i]->name))
			return 1;
	return 0;
}

static int autocorrect;
static struct cmdnames aliases;

static int git_unknown_cmd_config(const char *var, const char *value, void *cb)
{
	const char *p;

	if (!strcmp(var, "help.autocorrect"))
		autocorrect = git_config_int(var,value);
	/* Also use aliases for command lookup */
	if (skip_prefix(var, "alias.", &p))
		add_cmdname(&aliases, p, strlen(p));

	return git_default_config(var, value, cb);
}

static int levenshtein_compare(const void *p1, const void *p2)
{
	const struct cmdname *const *c1 = p1, *const *c2 = p2;
	const char *s1 = (*c1)->name, *s2 = (*c2)->name;
	int l1 = (*c1)->len;
	int l2 = (*c2)->len;
	return l1 != l2 ? l1 - l2 : strcmp(s1, s2);
}

static void add_cmd_list(struct cmdnames *cmds, struct cmdnames *old)
{
	int i;
	ALLOC_GROW(cmds->names, cmds->cnt + old->cnt, cmds->alloc);

	for (i = 0; i < old->cnt; i++)
		cmds->names[cmds->cnt++] = old->names[i];
	FREE_AND_NULL(old->names);
	old->cnt = 0;
}

/* An empirically derived magic number */
#define SIMILARITY_FLOOR 7
#define SIMILAR_ENOUGH(x) ((x) < SIMILARITY_FLOOR)

static const char bad_interpreter_advice[] =
	N_("'%s' appears to be a git command, but we were not\n"
	"able to execute it. Maybe git-%s is broken?");

const char *help_unknown_cmd(const char *cmd)
{
	int i, n, best_similarity = 0;
	struct cmdnames main_cmds, other_cmds;
	struct cmdname_help *common_cmds;

	memset(&main_cmds, 0, sizeof(main_cmds));
	memset(&other_cmds, 0, sizeof(other_cmds));
	memset(&aliases, 0, sizeof(aliases));

	read_early_config(git_unknown_cmd_config, NULL);

	load_command_list("git-", &main_cmds, &other_cmds);

	add_cmd_list(&main_cmds, &aliases);
	add_cmd_list(&main_cmds, &other_cmds);
	QSORT(main_cmds.names, main_cmds.cnt, cmdname_compare);
	uniq(&main_cmds);

	extract_cmds(&common_cmds, common_mask);

	/* This abuses cmdname->len for levenshtein distance */
	for (i = 0, n = 0; i < main_cmds.cnt; i++) {
		int cmp = 0; /* avoid compiler stupidity */
		const char *candidate = main_cmds.names[i]->name;

		/*
		 * An exact match means we have the command, but
		 * for some reason exec'ing it gave us ENOENT; probably
		 * it's a bad interpreter in the #! line.
		 */
		if (!strcmp(candidate, cmd))
			die(_(bad_interpreter_advice), cmd, cmd);

		/* Does the candidate appear in common_cmds list? */
		while (common_cmds[n].name &&
		       (cmp = strcmp(common_cmds[n].name, candidate)) < 0)
			n++;
		if (common_cmds[n].name && !cmp) {
			/* Yes, this is one of the common commands */
			n++; /* use the entry from common_cmds[] */
			if (starts_with(candidate, cmd)) {
				/* Give prefix match a very good score */
				main_cmds.names[i]->len = 0;
				continue;
			}
		}

		main_cmds.names[i]->len =
			levenshtein(cmd, candidate, 0, 2, 1, 3) + 1;
	}
	FREE_AND_NULL(common_cmds);

	QSORT(main_cmds.names, main_cmds.cnt, levenshtein_compare);

	if (!main_cmds.cnt)
		die(_("Uh oh. Your system reports no Git commands at all."));

	/* skip and count prefix matches */
	for (n = 0; n < main_cmds.cnt && !main_cmds.names[n]->len; n++)
		; /* still counting */

	if (main_cmds.cnt <= n) {
		/* prefix matches with everything? that is too ambiguous */
		best_similarity = SIMILARITY_FLOOR + 1;
	} else {
		/* count all the most similar ones */
		for (best_similarity = main_cmds.names[n++]->len;
		     (n < main_cmds.cnt &&
		      best_similarity == main_cmds.names[n]->len);
		     n++)
			; /* still counting */
	}
	if (autocorrect && n == 1 && SIMILAR_ENOUGH(best_similarity)) {
		const char *assumed = main_cmds.names[0]->name;
		main_cmds.names[0] = NULL;
		clean_cmdnames(&main_cmds);
		fprintf_ln(stderr,
			   _("WARNING: You called a Git command named '%s', "
			     "which does not exist."),
			   cmd);
		if (autocorrect < 0)
			fprintf_ln(stderr,
				   _("Continuing under the assumption that "
				     "you meant '%s'."),
				   assumed);
		else {
			fprintf_ln(stderr,
				   _("Continuing in %0.1f seconds, "
				     "assuming that you meant '%s'."),
				   (float)autocorrect/10.0, assumed);
			sleep_millisec(autocorrect * 100);
		}
		return assumed;
	}

	fprintf_ln(stderr, _("git: '%s' is not a git command. See 'git --help'."), cmd);

	if (SIMILAR_ENOUGH(best_similarity)) {
		fprintf_ln(stderr,
			   Q_("\nThe most similar command is",
			      "\nThe most similar commands are",
			   n));

		for (i = 0; i < n; i++)
			fprintf(stderr, "\t%s\n", main_cmds.names[i]->name);
	}

	exit(1);
}

int cmd_version(int argc, const char **argv, const char *prefix)
{
	int build_options = 0;
	const char * const usage[] = {
		N_("git version [<options>]"),
		NULL
	};
	struct option options[] = {
		OPT_BOOL(0, "build-options", &build_options,
			 "also print build options"),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options, usage, 0);

	/*
	 * The format of this string should be kept stable for compatibility
	 * with external projects that rely on the output of "git version".
	 *
	 * Always show the version, even if other options are given.
	 */
	printf("git version %s\n", git_version_string);

	if (build_options) {
		printf("cpu: %s\n", GIT_HOST_CPU);
		if (git_built_from_commit_string[0])
			printf("built from commit: %s\n",
			       git_built_from_commit_string);
		else
			printf("no commit associated with this build\n");
		printf("sizeof-long: %d\n", (int)sizeof(long));
		printf("sizeof-size_t: %d\n", (int)sizeof(size_t));
		/* NEEDSWORK: also save and output GIT-BUILD_OPTIONS? */
	}
	return 0;
}

struct similar_ref_cb {
	const char *base_ref;
	struct string_list *similar_refs;
};

static int append_similar_ref(const char *refname, const struct object_id *oid,
			      int flags, void *cb_data)
{
	struct similar_ref_cb *cb = (struct similar_ref_cb *)(cb_data);
	char *branch = strrchr(refname, '/') + 1;

	/* A remote branch of the same name is deemed similar */
	if (starts_with(refname, "refs/remotes/") &&
	    !strcmp(branch, cb->base_ref))
		string_list_append_nodup(cb->similar_refs,
					 shorten_unambiguous_ref(refname, 1));
	return 0;
}

static struct string_list guess_refs(const char *ref)
{
	struct similar_ref_cb ref_cb;
	struct string_list similar_refs = STRING_LIST_INIT_DUP;

	ref_cb.base_ref = ref;
	ref_cb.similar_refs = &similar_refs;
	for_each_ref(append_similar_ref, &ref_cb);
	return similar_refs;
}

NORETURN void help_unknown_ref(const char *ref, const char *cmd,
			       const char *error)
{
	int i;
	struct string_list suggested_refs = guess_refs(ref);

	fprintf_ln(stderr, _("%s: %s - %s"), cmd, ref, error);

	if (suggested_refs.nr > 0) {
		fprintf_ln(stderr,
			   Q_("\nDid you mean this?",
			      "\nDid you mean one of these?",
			      suggested_refs.nr));
		for (i = 0; i < suggested_refs.nr; i++)
			fprintf(stderr, "\t%s\n", suggested_refs.items[i].string);
	}

	string_list_clear(&suggested_refs, 0);
	exit(1);
}
#include "cache.h"
#include "config.h"
#include "builtin.h"
#include "exec-cmd.h"
#include "run-command.h"
#include "levenshtein.h"
#include "help.h"
#include "command-list.h"
#include "string-list.h"
#include "column.h"
#include "version.h"
#include "refs.h"
#include "parse-options.h"

struct category_description {
	uint32_t category;
	const char *desc;
};
static uint32_t common_mask =
	CAT_init | CAT_worktree | CAT_info |
	CAT_history | CAT_remote;
static struct category_description common_categories[] = {
	{ CAT_init, N_("start a working area (see also: git help tutorial)") },
	{ CAT_worktree, N_("work on the current change (see also: git help everyday)") },
	{ CAT_info, N_("examine the history and state (see also: git help revisions)") },
	{ CAT_history, N_("grow, mark and tweak your common history") },
	{ CAT_remote, N_("collaborate (see also: git help workflows)") },
	{ 0, NULL }
};
static struct category_description main_categories[] = {
	{ CAT_mainporcelain, N_("Main Porcelain Commands") },
	{ CAT_ancillarymanipulators, N_("Ancillary Commands / Manipulators") },
	{ CAT_ancillaryinterrogators, N_("Ancillary Commands / Interrogators") },
	{ CAT_foreignscminterface, N_("Interacting with Others") },
	{ CAT_plumbingmanipulators, N_("Low-level Commands / Manipulators") },
	{ CAT_plumbinginterrogators, N_("Low-level Commands / Interrogators") },
	{ CAT_synchingrepositories, N_("Low-level Commands / Syncing Repositories") },
	{ CAT_purehelpers, N_("Low-level Commands / Internal Helpers") },
	{ 0, NULL }
};

static const char *drop_prefix(const char *name, uint32_t category)
{
	const char *new_name;

	if (skip_prefix(name, "git-", &new_name))
		return new_name;
	if (category == CAT_guide && skip_prefix(name, "git", &new_name))
		return new_name;
	return name;

}

static void extract_cmds(struct cmdname_help **p_cmds, uint32_t mask)
{
	int i, nr = 0;
	struct cmdname_help *cmds;

	if (ARRAY_SIZE(command_list) == 0)
		BUG("empty command_list[] is a sign of broken generate-cmdlist.sh");

	ALLOC_ARRAY(cmds, ARRAY_SIZE(command_list) + 1);

	for (i = 0; i < ARRAY_SIZE(command_list); i++) {
		const struct cmdname_help *cmd = command_list + i;

		if (!(cmd->category & mask))
			continue;

		cmds[nr] = *cmd;
		cmds[nr].name = drop_prefix(cmd->name, cmd->category);

		nr++;
	}
	cmds[nr].name = NULL;
	*p_cmds = cmds;
}

static void print_command_list(const struct cmdname_help *cmds,
			       uint32_t mask, int longest)
{
	int i;

	for (i = 0; cmds[i].name; i++) {
		if (cmds[i].category & mask) {
			size_t len = strlen(cmds[i].name);
			printf("   %s   ", cmds[i].name);
			if (longest > len)
				mput_char(' ', longest - len);
			puts(_(cmds[i].help));
		}
	}
}

static int cmd_name_cmp(const void *elem1, const void *elem2)
{
	const struct cmdname_help *e1 = elem1;
	const struct cmdname_help *e2 = elem2;

	return strcmp(e1->name, e2->name);
}

static void print_cmd_by_category(const struct category_description *catdesc,
				  int *longest_p)
{
	struct cmdname_help *cmds;
	int longest = 0;
	int i, nr = 0;
	uint32_t mask = 0;

	for (i = 0; catdesc[i].desc; i++)
		mask |= catdesc[i].category;

	extract_cmds(&cmds, mask);

	for (i = 0; cmds[i].name; i++, nr++) {
		if (longest < strlen(cmds[i].name))
			longest = strlen(cmds[i].name);
	}
	QSORT(cmds, nr, cmd_name_cmp);

	for (i = 0; catdesc[i].desc; i++) {
		uint32_t mask = catdesc[i].category;
		const char *desc = catdesc[i].desc;

		printf("\n%s\n", _(desc));
		print_command_list(cmds, mask, longest);
	}
	free(cmds);
	if (longest_p)
		*longest_p = longest;
}

void add_cmdname(struct cmdnames *cmds, const char *name, int len)
{
	struct cmdname *ent;
	FLEX_ALLOC_MEM(ent, name, name, len);
	ent->len = len;

	ALLOC_GROW(cmds->names, cmds->cnt + 1, cmds->alloc);
	cmds->names[cmds->cnt++] = ent;
}

static void clean_cmdnames(struct cmdnames *cmds)
{
	int i;
	for (i = 0; i < cmds->cnt; ++i)
		free(cmds->names[i]);
	free(cmds->names);
	cmds->cnt = 0;
	cmds->alloc = 0;
}

static int cmdname_compare(const void *a_, const void *b_)
{
	struct cmdname *a = *(struct cmdname **)a_;
	struct cmdname *b = *(struct cmdname **)b_;
	return strcmp(a->name, b->name);
}

static void uniq(struct cmdnames *cmds)
{
	int i, j;

	if (!cmds->cnt)
		return;

	for (i = j = 1; i < cmds->cnt; i++) {
		if (!strcmp(cmds->names[i]->name, cmds->names[j-1]->name))
			free(cmds->names[i]);
		else
			cmds->names[j++] = cmds->names[i];
	}

	cmds->cnt = j;
}

void exclude_cmds(struct cmdnames *cmds, struct cmdnames *excludes)
{
	int ci, cj, ei;
	int cmp;

	ci = cj = ei = 0;
	while (ci < cmds->cnt && ei < excludes->cnt) {
		cmp = strcmp(cmds->names[ci]->name, excludes->names[ei]->name);
		if (cmp < 0)
			cmds->names[cj++] = cmds->names[ci++];
		else if (cmp == 0) {
			ei++;
			free(cmds->names[ci++]);
		} else if (cmp > 0)
			ei++;
	}

	while (ci < cmds->cnt)
		cmds->names[cj++] = cmds->names[ci++];

	cmds->cnt = cj;
}

static void pretty_print_cmdnames(struct cmdnames *cmds, unsigned int colopts)
{
	struct string_list list = STRING_LIST_INIT_NODUP;
	struct column_options copts;
	int i;

	for (i = 0; i < cmds->cnt; i++)
		string_list_append(&list, cmds->names[i]->name);
	/*
	 * always enable column display, we only consult column.*
	 * about layout strategy and stuff
	 */
	colopts = (colopts & ~COL_ENABLE_MASK) | COL_ENABLED;
	memset(&copts, 0, sizeof(copts));
	copts.indent = "  ";
	copts.padding = 2;
	print_columns(&list, colopts, &copts);
	string_list_clear(&list, 0);
}

static void list_commands_in_dir(struct cmdnames *cmds,
					 const char *path,
					 const char *prefix)
{
	DIR *dir = opendir(path);
	struct dirent *de;
	struct strbuf buf = STRBUF_INIT;
	int len;

	if (!dir)
		return;
	if (!prefix)
		prefix = "git-";

	strbuf_addf(&buf, "%s/", path);
	len = buf.len;

	while ((de = readdir(dir)) != NULL) {
		const char *ent;
		size_t entlen;

		if (!skip_prefix(de->d_name, prefix, &ent))
			continue;

		strbuf_setlen(&buf, len);
		strbuf_addstr(&buf, de->d_name);
		if (!is_executable(buf.buf))
			continue;

		entlen = strlen(ent);
		strip_suffix(ent, ".exe", &entlen);

		add_cmdname(cmds, ent, entlen);
	}
	closedir(dir);
	strbuf_release(&buf);
}

void load_command_list(const char *prefix,
		struct cmdnames *main_cmds,
		struct cmdnames *other_cmds)
{
	const char *env_path = getenv("PATH");
	const char *exec_path = git_exec_path();

	if (exec_path) {
		list_commands_in_dir(main_cmds, exec_path, prefix);
		QSORT(main_cmds->names, main_cmds->cnt, cmdname_compare);
		uniq(main_cmds);
	}

	if (env_path) {
		char *paths, *path, *colon;
		path = paths = xstrdup(env_path);
		while (1) {
			if ((colon = strchr(path, PATH_SEP)))
				*colon = 0;
			if (!exec_path || strcmp(path, exec_path))
				list_commands_in_dir(other_cmds, path, prefix);

			if (!colon)
				break;
			path = colon + 1;
		}
		free(paths);

		QSORT(other_cmds->names, other_cmds->cnt, cmdname_compare);
		uniq(other_cmds);
	}
	exclude_cmds(other_cmds, main_cmds);
}

void list_commands(unsigned int colopts,
		   struct cmdnames *main_cmds, struct cmdnames *other_cmds)
{
	if (main_cmds->cnt) {
		const char *exec_path = git_exec_path();
		printf_ln(_("available git commands in '%s'"), exec_path);
		putchar('\n');
		pretty_print_cmdnames(main_cmds, colopts);
		putchar('\n');
	}

	if (other_cmds->cnt) {
		printf_ln(_("git commands available from elsewhere on your $PATH"));
		putchar('\n');
		pretty_print_cmdnames(other_cmds, colopts);
		putchar('\n');
	}
}

void list_common_cmds_help(void)
{
	puts(_("These are common Git commands used in various situations:"));
	print_cmd_by_category(common_categories, NULL);
}

void list_all_main_cmds(struct string_list *list)
{
	struct cmdnames main_cmds, other_cmds;
	int i;

	memset(&main_cmds, 0, sizeof(main_cmds));
	memset(&other_cmds, 0, sizeof(other_cmds));
	load_command_list("git-", &main_cmds, &other_cmds);

	for (i = 0; i < main_cmds.cnt; i++)
		string_list_append(list, main_cmds.names[i]->name);

	clean_cmdnames(&main_cmds);
	clean_cmdnames(&other_cmds);
}

void list_all_other_cmds(struct string_list *list)
{
	struct cmdnames main_cmds, other_cmds;
	int i;

	memset(&main_cmds, 0, sizeof(main_cmds));
	memset(&other_cmds, 0, sizeof(other_cmds));
	load_command_list("git-", &main_cmds, &other_cmds);

	for (i = 0; i < other_cmds.cnt; i++)
		string_list_append(list, other_cmds.names[i]->name);

	clean_cmdnames(&main_cmds);
	clean_cmdnames(&other_cmds);
}

void list_cmds_by_category(struct string_list *list,
			   const char *cat)
{
	int i, n = ARRAY_SIZE(command_list);
	uint32_t cat_id = 0;

	for (i = 0; category_names[i]; i++) {
		if (!strcmp(cat, category_names[i])) {
			cat_id = 1UL << i;
			break;
		}
	}
	if (!cat_id)
		die(_("unsupported command listing type '%s'"), cat);

	for (i = 0; i < n; i++) {
		struct cmdname_help *cmd = command_list + i;

		if (!(cmd->category & cat_id))
			continue;
		string_list_append(list, drop_prefix(cmd->name, cmd->category));
	}
}

void list_cmds_by_config(struct string_list *list)
{
	const char *cmd_list;

	if (git_config_get_string_const("completion.commands", &cmd_list))
		return;

	string_list_sort(list);
	string_list_remove_duplicates(list, 0);

	while (*cmd_list) {
		struct strbuf sb = STRBUF_INIT;
		const char *p = strchrnul(cmd_list, ' ');

		strbuf_add(&sb, cmd_list, p - cmd_list);
		if (sb.buf[0] == '-')
			string_list_remove(list, sb.buf + 1, 0);
		else
			string_list_insert(list, sb.buf);
		strbuf_release(&sb);
		while (*p == ' ')
			p++;
		cmd_list = p;
	}
}

void list_common_guides_help(void)
{
	struct category_description catdesc[] = {
		{ CAT_guide, N_("The common Git guides are:") },
		{ 0, NULL }
	};
	print_cmd_by_category(catdesc, NULL);
	putchar('\n');
}

struct slot_expansion {
	const char *prefix;
	const char *placeholder;
	void (*fn)(struct string_list *list, const char *prefix);
	int found;
};

void list_config_help(int for_human)
{
	struct slot_expansion slot_expansions[] = {
		{ "advice", "*", list_config_advices },
		{ "color.branch", "<slot>", list_config_color_branch_slots },
		{ "color.decorate", "<slot>", list_config_color_decorate_slots },
		{ "color.diff", "<slot>", list_config_color_diff_slots },
		{ "color.grep", "<slot>", list_config_color_grep_slots },
		{ "color.interactive", "<slot>", list_config_color_interactive_slots },
		{ "color.remote", "<slot>", list_config_color_sideband_slots },
		{ "color.status", "<slot>", list_config_color_status_slots },
		{ "fsck", "<msg-id>", list_config_fsck_msg_ids },
		{ "receive.fsck", "<msg-id>", list_config_fsck_msg_ids },
		{ NULL, NULL, NULL }
	};
	const char **p;
	struct slot_expansion *e;
	struct string_list keys = STRING_LIST_INIT_DUP;
	int i;

	for (p = config_name_list; *p; p++) {
		const char *var = *p;
		struct strbuf sb = STRBUF_INIT;

		for (e = slot_expansions; e->prefix; e++) {

			strbuf_reset(&sb);
			strbuf_addf(&sb, "%s.%s", e->prefix, e->placeholder);
			if (!strcasecmp(var, sb.buf)) {
				e->fn(&keys, e->prefix);
				e->found++;
				break;
			}
		}
		strbuf_release(&sb);
		if (!e->prefix)
			string_list_append(&keys, var);
	}

	for (e = slot_expansions; e->prefix; e++)
		if (!e->found)
			BUG("slot_expansion %s.%s is not used",
			    e->prefix, e->placeholder);

	string_list_sort(&keys);
	for (i = 0; i < keys.nr; i++) {
		const char *var = keys.items[i].string;
		const char *wildcard, *tag, *cut;

		if (for_human) {
			puts(var);
			continue;
		}

		wildcard = strchr(var, '*');
		tag = strchr(var, '<');

		if (!wildcard && !tag) {
			puts(var);
			continue;
		}

		if (wildcard && !tag)
			cut = wildcard;
		else if (!wildcard && tag)
			cut = tag;
		else
			cut = wildcard < tag ? wildcard : tag;

		/*
		 * We may produce duplicates, but that's up to
		 * git-completion.bash to handle
		 */
		printf("%.*s\n", (int)(cut - var), var);
	}
	string_list_clear(&keys, 0);
}

static int get_alias(const char *var, const char *value, void *data)
{
	struct string_list *list = data;

	if (skip_prefix(var, "alias.", &var))
		string_list_append(list, var)->util = xstrdup(value);

	return 0;
}

void list_all_cmds_help(void)
{
	struct string_list others = STRING_LIST_INIT_DUP;
	struct string_list alias_list = STRING_LIST_INIT_DUP;
	struct cmdname_help *aliases;
	int i, longest;

	printf_ln(_("See 'git help <command>' to read about a specific subcommand"));
	print_cmd_by_category(main_categories, &longest);

	list_all_other_cmds(&others);
	if (others.nr)
		printf("\n%s\n", _("External commands"));
	for (i = 0; i < others.nr; i++)
		printf("   %s\n", others.items[i].string);
	string_list_clear(&others, 0);

	git_config(get_alias, &alias_list);
	string_list_sort(&alias_list);

	for (i = 0; i < alias_list.nr; i++) {
		size_t len = strlen(alias_list.items[i].string);
		if (longest < len)
			longest = len;
	}

	if (alias_list.nr) {
		printf("\n%s\n", _("Command aliases"));
		ALLOC_ARRAY(aliases, alias_list.nr + 1);
		for (i = 0; i < alias_list.nr; i++) {
			aliases[i].name = alias_list.items[i].string;
			aliases[i].help = alias_list.items[i].util;
			aliases[i].category = 1;
		}
		aliases[alias_list.nr].name = NULL;
		print_command_list(aliases, 1, longest);
		free(aliases);
	}
	string_list_clear(&alias_list, 1);
}

int is_in_cmdlist(struct cmdnames *c, const char *s)
{
	int i;
	for (i = 0; i < c->cnt; i++)
		if (!strcmp(s, c->names[i]->name))
			return 1;
	return 0;
}

static int autocorrect;
static struct cmdnames aliases;

static int git_unknown_cmd_config(const char *var, const char *value, void *cb)
{
	const char *p;

	if (!strcmp(var, "help.autocorrect"))
		autocorrect = git_config_int(var,value);
	/* Also use aliases for command lookup */
	if (skip_prefix(var, "alias.", &p))
		add_cmdname(&aliases, p, strlen(p));

	return git_default_config(var, value, cb);
}

static int levenshtein_compare(const void *p1, const void *p2)
{
	const struct cmdname *const *c1 = p1, *const *c2 = p2;
	const char *s1 = (*c1)->name, *s2 = (*c2)->name;
	int l1 = (*c1)->len;
	int l2 = (*c2)->len;
	return l1 != l2 ? l1 - l2 : strcmp(s1, s2);
}

static void add_cmd_list(struct cmdnames *cmds, struct cmdnames *old)
{
	int i;
	ALLOC_GROW(cmds->names, cmds->cnt + old->cnt, cmds->alloc);

	for (i = 0; i < old->cnt; i++)
		cmds->names[cmds->cnt++] = old->names[i];
	FREE_AND_NULL(old->names);
	old->cnt = 0;
}

/* An empirically derived magic number */
#define SIMILARITY_FLOOR 7
#define SIMILAR_ENOUGH(x) ((x) < SIMILARITY_FLOOR)

static const char bad_interpreter_advice[] =
	N_("'%s' appears to be a git command, but we were not\n"
	"able to execute it. Maybe git-%s is broken?");

const char *help_unknown_cmd(const char *cmd)
{
	int i, n, best_similarity = 0;
	struct cmdnames main_cmds, other_cmds;
	struct cmdname_help *common_cmds;

	memset(&main_cmds, 0, sizeof(main_cmds));
	memset(&other_cmds, 0, sizeof(other_cmds));
	memset(&aliases, 0, sizeof(aliases));

	read_early_config(git_unknown_cmd_config, NULL);

	load_command_list("git-", &main_cmds, &other_cmds);

	add_cmd_list(&main_cmds, &aliases);
	add_cmd_list(&main_cmds, &other_cmds);
	QSORT(main_cmds.names, main_cmds.cnt, cmdname_compare);
	uniq(&main_cmds);

	extract_cmds(&common_cmds, common_mask);

	/* This abuses cmdname->len for levenshtein distance */
	for (i = 0, n = 0; i < main_cmds.cnt; i++) {
		int cmp = 0; /* avoid compiler stupidity */
		const char *candidate = main_cmds.names[i]->name;

		/*
		 * An exact match means we have the command, but
		 * for some reason exec'ing it gave us ENOENT; probably
		 * it's a bad interpreter in the #! line.
		 */
		if (!strcmp(candidate, cmd))
			die(_(bad_interpreter_advice), cmd, cmd);

		/* Does the candidate appear in common_cmds list? */
		while (common_cmds[n].name &&
		       (cmp = strcmp(common_cmds[n].name, candidate)) < 0)
			n++;
		if (common_cmds[n].name && !cmp) {
			/* Yes, this is one of the common commands */
			n++; /* use the entry from common_cmds[] */
			if (starts_with(candidate, cmd)) {
				/* Give prefix match a very good score */
				main_cmds.names[i]->len = 0;
				continue;
			}
		}

		main_cmds.names[i]->len =
			levenshtein(cmd, candidate, 0, 2, 1, 3) + 1;
	}
	FREE_AND_NULL(common_cmds);

	QSORT(main_cmds.names, main_cmds.cnt, levenshtein_compare);

	if (!main_cmds.cnt)
		die(_("Uh oh. Your system reports no Git commands at all."));

	/* skip and count prefix matches */
	for (n = 0; n < main_cmds.cnt && !main_cmds.names[n]->len; n++)
		; /* still counting */

	if (main_cmds.cnt <= n) {
		/* prefix matches with everything? that is too ambiguous */
		best_similarity = SIMILARITY_FLOOR + 1;
	} else {
		/* count all the most similar ones */
		for (best_similarity = main_cmds.names[n++]->len;
		     (n < main_cmds.cnt &&
		      best_similarity == main_cmds.names[n]->len);
		     n++)
			; /* still counting */
	}
	if (autocorrect && n == 1 && SIMILAR_ENOUGH(best_similarity)) {
		const char *assumed = main_cmds.names[0]->name;
		main_cmds.names[0] = NULL;
		clean_cmdnames(&main_cmds);
		fprintf_ln(stderr,
			   _("WARNING: You called a Git command named '%s', "
			     "which does not exist."),
			   cmd);
		if (autocorrect < 0)
			fprintf_ln(stderr,
				   _("Continuing under the assumption that "
				     "you meant '%s'."),
				   assumed);
		else {
			fprintf_ln(stderr,
				   _("Continuing in %0.1f seconds, "
				     "assuming that you meant '%s'."),
				   (float)autocorrect/10.0, assumed);
			sleep_millisec(autocorrect * 100);
		}
		return assumed;
	}

	fprintf_ln(stderr, _("git: '%s' is not a git command. See 'git --help'."), cmd);

	if (SIMILAR_ENOUGH(best_similarity)) {
		fprintf_ln(stderr,
			   Q_("\nThe most similar command is",
			      "\nThe most similar commands are",
			   n));

		for (i = 0; i < n; i++)
			fprintf(stderr, "\t%s\n", main_cmds.names[i]->name);
	}

	exit(1);
}

int cmd_version(int argc, const char **argv, const char *prefix)
{
	int build_options = 0;
	const char * const usage[] = {
		N_("git version [<options>]"),
		NULL
	};
	struct option options[] = {
		OPT_BOOL(0, "build-options", &build_options,
			 "also print build options"),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, options, usage, 0);

	/*
	 * The format of this string should be kept stable for compatibility
	 * with external projects that rely on the output of "git version".
	 *
	 * Always show the version, even if other options are given.
	 */
	printf("git version %s\n", git_version_string);

	if (build_options) {
		printf("cpu: %s\n", GIT_HOST_CPU);
		if (git_built_from_commit_string[0])
			printf("built from commit: %s\n",
			       git_built_from_commit_string);
		else
			printf("no commit associated with this build\n");
		printf("sizeof-long: %d\n", (int)sizeof(long));
		printf("sizeof-size_t: %d\n", (int)sizeof(size_t));
		/* NEEDSWORK: also save and output GIT-BUILD_OPTIONS? */
	}
	return 0;
}

struct similar_ref_cb {
	const char *base_ref;
	struct string_list *similar_refs;
};

static int append_similar_ref(const char *refname, const struct object_id *oid,
			      int flags, void *cb_data)
{
	struct similar_ref_cb *cb = (struct similar_ref_cb *)(cb_data);
	char *branch = strrchr(refname, '/') + 1;

	/* A remote branch of the same name is deemed similar */
	if (starts_with(refname, "refs/remotes/") &&
	    !strcmp(branch, cb->base_ref))
		string_list_append_nodup(cb->similar_refs,
					 shorten_unambiguous_ref(refname, 1));
	return 0;
}

static struct string_list guess_refs(const char *ref)
{
	struct similar_ref_cb ref_cb;
	struct string_list similar_refs = STRING_LIST_INIT_DUP;

	ref_cb.base_ref = ref;
	ref_cb.similar_refs = &similar_refs;
	for_each_ref(append_similar_ref, &ref_cb);
	return similar_refs;
}

NORETURN void help_unknown_ref(const char *ref, const char *cmd,
			       const char *error)
{
	int i;
	struct string_list suggested_refs = guess_refs(ref);

	fprintf_ln(stderr, _("%s: %s - %s"), cmd, ref, error);

	if (suggested_refs.nr > 0) {
		fprintf_ln(stderr,
			   Q_("\nDid you mean this?",
			      "\nDid you mean one of these?",
			      suggested_refs.nr));
		for (i = 0; i < suggested_refs.nr; i++)
			fprintf(stderr, "\t%s\n", suggested_refs.items[i].string);
	}

	string_list_clear(&suggested_refs, 0);
	exit(1);
}
#include "cache.h"
#include "object.h"
#include "blob.h"
#include "commit.h"
#include "tag.h"
#include "tree.h"
#include "delta.h"
#include "pack.h"
#include "csum-file.h"
#include "tree-walk.h"
#include <sys/time.h>
#include <signal.h>

static const char pack_usage[] = "git-pack-objects [-q] [--no-reuse-delta] [--non-empty] [--local] [--incremental] [--window=N] [--depth=N] {--stdout | base-name} < object-list";

struct object_entry {
	unsigned char sha1[20];
	unsigned long size;	/* uncompressed size */
	unsigned long offset;	/* offset into the final pack file;
				 * nonzero if already written.
				 */
	unsigned int depth;	/* delta depth */
	unsigned int delta_limit;	/* base adjustment for in-pack delta */
	unsigned int hash;	/* name hint hash */
	enum object_type type;
	enum object_type in_pack_type;	/* could be delta */
	unsigned long delta_size;	/* delta data size (uncompressed) */
	struct object_entry *delta;	/* delta base object */
	struct packed_git *in_pack; 	/* already in pack */
	unsigned int in_pack_offset;
	struct object_entry *delta_child; /* delitified objects who bases me */
	struct object_entry *delta_sibling; /* other deltified objects who
					     * uses the same base as me
					     */
	int preferred_base;	/* we do not pack this, but is encouraged to
				 * be used as the base objectto delta huge
				 * objects against.
				 */
};

/*
 * Objects we are going to pack are colected in objects array (dynamically
 * expanded).  nr_objects & nr_alloc controls this array.  They are stored
 * in the order we see -- typically rev-list --objects order that gives us
 * nice "minimum seek" order.
 *
 * sorted-by-sha ans sorted-by-type are arrays of pointers that point at
 * elements in the objects array.  The former is used to build the pack
 * index (lists object names in the ascending order to help offset lookup),
 * and the latter is used to group similar things together by try_delta()
 * heuristics.
 */

static unsigned char object_list_sha1[20];
static int non_empty = 0;
static int no_reuse_delta = 0;
static int local = 0;
static int incremental = 0;
static struct object_entry **sorted_by_sha, **sorted_by_type;
static struct object_entry *objects = NULL;
static int nr_objects = 0, nr_alloc = 0, nr_result = 0;
static const char *base_name;
static unsigned char pack_file_sha1[20];
static int progress = 1;
static volatile sig_atomic_t progress_update = 0;

/*
 * The object names in objects array are hashed with this hashtable,
 * to help looking up the entry by object name.  Binary search from
 * sorted_by_sha is also possible but this was easier to code and faster.
 * This hashtable is built after all the objects are seen.
 */
static int *object_ix = NULL;
static int object_ix_hashsz = 0;

/*
 * Pack index for existing packs give us easy access to the offsets into
 * corresponding pack file where each object's data starts, but the entries
 * do not store the size of the compressed representation (uncompressed
 * size is easily available by examining the pack entry header).  We build
 * a hashtable of existing packs (pack_revindex), and keep reverse index
 * here -- pack index file is sorted by object name mapping to offset; this
 * pack_revindex[].revindex array is an ordered list of offsets, so if you
 * know the offset of an object, next offset is where its packed
 * representation ends.
 */
struct pack_revindex {
	struct packed_git *p;
	unsigned long *revindex;
} *pack_revindex = NULL;
static int pack_revindex_hashsz = 0;

/*
 * stats
 */
static int written = 0;
static int written_delta = 0;
static int reused = 0;
static int reused_delta = 0;

static int pack_revindex_ix(struct packed_git *p)
{
	unsigned long ui = (unsigned long)p;
	int i;

	ui = ui ^ (ui >> 16); /* defeat structure alignment */
	i = (int)(ui % pack_revindex_hashsz);
	while (pack_revindex[i].p) {
		if (pack_revindex[i].p == p)
			return i;
		if (++i == pack_revindex_hashsz)
			i = 0;
	}
	return -1 - i;
}

static void prepare_pack_ix(void)
{
	int num;
	struct packed_git *p;
	for (num = 0, p = packed_git; p; p = p->next)
		num++;
	if (!num)
		return;
	pack_revindex_hashsz = num * 11;
	pack_revindex = xcalloc(sizeof(*pack_revindex), pack_revindex_hashsz);
	for (p = packed_git; p; p = p->next) {
		num = pack_revindex_ix(p);
		num = - 1 - num;
		pack_revindex[num].p = p;
	}
	/* revindex elements are lazily initialized */
}

static int cmp_offset(const void *a_, const void *b_)
{
	unsigned long a = *(unsigned long *) a_;
	unsigned long b = *(unsigned long *) b_;
	if (a < b)
		return -1;
	else if (a == b)
		return 0;
	else
		return 1;
}

/*
 * Ordered list of offsets of objects in the pack.
 */
static void prepare_pack_revindex(struct pack_revindex *rix)
{
	struct packed_git *p = rix->p;
	int num_ent = num_packed_objects(p);
	int i;
	void *index = p->index_base + 256;

	rix->revindex = xmalloc(sizeof(unsigned long) * (num_ent + 1));
	for (i = 0; i < num_ent; i++) {
		long hl = *((long *)(index + 24 * i));
		rix->revindex[i] = ntohl(hl);
	}
	/* This knows the pack format -- the 20-byte trailer
	 * follows immediately after the last object data.
	 */
	rix->revindex[num_ent] = p->pack_size - 20;
	qsort(rix->revindex, num_ent, sizeof(unsigned long), cmp_offset);
}

static unsigned long find_packed_object_size(struct packed_git *p,
					     unsigned long ofs)
{
	int num;
	int lo, hi;
	struct pack_revindex *rix;
	unsigned long *revindex;
	num = pack_revindex_ix(p);
	if (num < 0)
		die("internal error: pack revindex uninitialized");
	rix = &pack_revindex[num];
	if (!rix->revindex)
		prepare_pack_revindex(rix);
	revindex = rix->revindex;
	lo = 0;
	hi = num_packed_objects(p) + 1;
	do {
		int mi = (lo + hi) / 2;
		if (revindex[mi] == ofs) {
			return revindex[mi+1] - ofs;
		}
		else if (ofs < revindex[mi])
			hi = mi;
		else
			lo = mi + 1;
	} while (lo < hi);
	die("internal error: pack revindex corrupt");
}

static void *delta_against(void *buf, unsigned long size, struct object_entry *entry)
{
	unsigned long othersize, delta_size;
	char type[10];
	void *otherbuf = read_sha1_file(entry->delta->sha1, type, &othersize);
	void *delta_buf;

	if (!otherbuf)
		die("unable to read %s", sha1_to_hex(entry->delta->sha1));
        delta_buf = diff_delta(otherbuf, othersize,
			       buf, size, &delta_size, 0);
        if (!delta_buf || delta_size != entry->delta_size)
        	die("delta size changed");
        free(buf);
        free(otherbuf);
	return delta_buf;
}

/*
 * The per-object header is a pretty dense thing, which is
 *  - first byte: low four bits are "size", then three bits of "type",
 *    and the high bit is "size continues".
 *  - each byte afterwards: low seven bits are size continuation,
 *    with the high bit being "size continues"
 */
static int encode_header(enum object_type type, unsigned long size, unsigned char *hdr)
{
	int n = 1;
	unsigned char c;

	if (type < OBJ_COMMIT || type > OBJ_DELTA)
		die("bad type %d", type);

	c = (type << 4) | (size & 15);
	size >>= 4;
	while (size) {
		*hdr++ = c | 0x80;
		c = size & 0x7f;
		size >>= 7;
		n++;
	}
	*hdr = c;
	return n;
}

static unsigned long write_object(struct sha1file *f,
				  struct object_entry *entry)
{
	unsigned long size;
	char type[10];
	void *buf;
	unsigned char header[10];
	unsigned hdrlen, datalen;
	enum object_type obj_type;
	int to_reuse = 0;

	if (entry->preferred_base)
		return 0;

	obj_type = entry->type;
	if (! entry->in_pack)
		to_reuse = 0;	/* can't reuse what we don't have */
	else if (obj_type == OBJ_DELTA)
		to_reuse = 1;	/* check_object() decided it for us */
	else if (obj_type != entry->in_pack_type)
		to_reuse = 0;	/* pack has delta which is unusable */
	else if (entry->delta)
		to_reuse = 0;	/* we want to pack afresh */
	else
		to_reuse = 1;	/* we have it in-pack undeltified,
				 * and we do not need to deltify it.
				 */

	if (! to_reuse) {
		buf = read_sha1_file(entry->sha1, type, &size);
		if (!buf)
			die("unable to read %s", sha1_to_hex(entry->sha1));
		if (size != entry->size)
			die("object %s size inconsistency (%lu vs %lu)",
			    sha1_to_hex(entry->sha1), size, entry->size);
		if (entry->delta) {
			buf = delta_against(buf, size, entry);
			size = entry->delta_size;
			obj_type = OBJ_DELTA;
		}
		/*
		 * The object header is a byte of 'type' followed by zero or
		 * more bytes of length.  For deltas, the 20 bytes of delta
		 * sha1 follows that.
		 */
		hdrlen = encode_header(obj_type, size, header);
		sha1write(f, header, hdrlen);

		if (entry->delta) {
			sha1write(f, entry->delta, 20);
			hdrlen += 20;
		}
		datalen = sha1write_compressed(f, buf, size);
		free(buf);
	}
	else {
		struct packed_git *p = entry->in_pack;
		use_packed_git(p);

		datalen = find_packed_object_size(p, entry->in_pack_offset);
		buf = p->pack_base + entry->in_pack_offset;
		sha1write(f, buf, datalen);
		unuse_packed_git(p);
		hdrlen = 0; /* not really */
		if (obj_type == OBJ_DELTA)
			reused_delta++;
		reused++;
	}
	if (obj_type == OBJ_DELTA)
		written_delta++;
	written++;
	return hdrlen + datalen;
}

static unsigned long write_one(struct sha1file *f,
			       struct object_entry *e,
			       unsigned long offset)
{
	if (e->offset)
		/* offset starts from header size and cannot be zero
		 * if it is written already.
		 */
		return offset;
	e->offset = offset;
	offset += write_object(f, e);
	/* if we are deltified, write out its base object. */
	if (e->delta)
		offset = write_one(f, e->delta, offset);
	return offset;
}

static void write_pack_file(void)
{
	int i;
	struct sha1file *f;
	unsigned long offset;
	struct pack_header hdr;
	unsigned last_percent = 999;
	int do_progress = 0;

	if (!base_name)
		f = sha1fd(1, "<stdout>");
	else {
		f = sha1create("%s-%s.%s", base_name,
			       sha1_to_hex(object_list_sha1), "pack");
		do_progress = progress;
	}
	if (do_progress)
		fprintf(stderr, "Writing %d objects.\n", nr_result);

	hdr.hdr_signature = htonl(PACK_SIGNATURE);
	hdr.hdr_version = htonl(PACK_VERSION);
	hdr.hdr_entries = htonl(nr_result);
	sha1write(f, &hdr, sizeof(hdr));
	offset = sizeof(hdr);
	if (!nr_result)
		goto done;
	for (i = 0; i < nr_objects; i++) {
		offset = write_one(f, objects + i, offset);
		if (do_progress) {
			unsigned percent = written * 100 / nr_result;
			if (progress_update || percent != last_percent) {
				fprintf(stderr, "%4u%% (%u/%u) done\r",
					percent, written, nr_result);
				progress_update = 0;
				last_percent = percent;
			}
		}
	}
	if (do_progress)
		fputc('\n', stderr);
 done:
	sha1close(f, pack_file_sha1, 1);
}

static void write_index_file(void)
{
	int i;
	struct sha1file *f = sha1create("%s-%s.%s", base_name,
					sha1_to_hex(object_list_sha1), "idx");
	struct object_entry **list = sorted_by_sha;
	struct object_entry **last = list + nr_result;
	unsigned int array[256];

	/*
	 * Write the first-level table (the list is sorted,
	 * but we use a 256-entry lookup to be able to avoid
	 * having to do eight extra binary search iterations).
	 */
	for (i = 0; i < 256; i++) {
		struct object_entry **next = list;
		while (next < last) {
			struct object_entry *entry = *next;
			if (entry->sha1[0] != i)
				break;
			next++;
		}
		array[i] = htonl(next - sorted_by_sha);
		list = next;
	}
	sha1write(f, array, 256 * sizeof(int));

	/*
	 * Write the actual SHA1 entries..
	 */
	list = sorted_by_sha;
	for (i = 0; i < nr_result; i++) {
		struct object_entry *entry = *list++;
		unsigned int offset = htonl(entry->offset);
		sha1write(f, &offset, 4);
		sha1write(f, entry->sha1, 20);
	}
	sha1write(f, pack_file_sha1, 20);
	sha1close(f, NULL, 1);
}

static int locate_object_entry_hash(const unsigned char *sha1)
{
	int i;
	unsigned int ui;
	memcpy(&ui, sha1, sizeof(unsigned int));
	i = ui % object_ix_hashsz;
	while (0 < object_ix[i]) {
		if (!memcmp(sha1, objects[object_ix[i]-1].sha1, 20))
			return i;
		if (++i == object_ix_hashsz)
			i = 0;
	}
	return -1 - i;
}

static struct object_entry *locate_object_entry(const unsigned char *sha1)
{
	int i;

	if (!object_ix_hashsz)
		return NULL;

	i = locate_object_entry_hash(sha1);
	if (0 <= i)
		return &objects[object_ix[i]-1];
	return NULL;
}

static void rehash_objects(void)
{
	int i;
	struct object_entry *oe;

	object_ix_hashsz = nr_objects * 3;
	if (object_ix_hashsz < 1024)
		object_ix_hashsz = 1024;
	object_ix = xrealloc(object_ix, sizeof(int) * object_ix_hashsz);
	memset(object_ix, 0, sizeof(int) * object_ix_hashsz);
	for (i = 0, oe = objects; i < nr_objects; i++, oe++) {
		int ix = locate_object_entry_hash(oe->sha1);
		if (0 <= ix)
			continue;
		ix = -1 - ix;
		object_ix[ix] = i + 1;
	}
}

struct name_path {
	struct name_path *up;
	const char *elem;
	int len;
};

#define DIRBITS 12

static unsigned name_hash(struct name_path *path, const char *name)
{
	struct name_path *p = path;
	const char *n = name + strlen(name);
	unsigned hash = 0, name_hash = 0, name_done = 0;

	if (n != name && n[-1] == '\n')
		n--;
	while (name <= --n) {
		unsigned char c = *n;
		if (c == '/' && !name_done) {
			name_hash = hash;
			name_done = 1;
			hash = 0;
		}
		hash = hash * 11 + c;
	}
	if (!name_done) {
		name_hash = hash;
		hash = 0;
	}
	for (p = path; p; p = p->up) {
		hash = hash * 11 + '/';
		n = p->elem + p->len;
		while (p->elem <= --n) {
			unsigned char c = *n;
			hash = hash * 11 + c;
		}
	}
	/*
	 * Make sure "Makefile" and "t/Makefile" are hashed separately
	 * but close enough.
	 */
	hash = (name_hash<<DIRBITS) | (hash & ((1U<<DIRBITS )-1));
	return hash;
}

static int add_object_entry(const unsigned char *sha1, unsigned hash, int exclude)
{
	unsigned int idx = nr_objects;
	struct object_entry *entry;
	struct packed_git *p;
	unsigned int found_offset = 0;
	struct packed_git *found_pack = NULL;
	int ix, status = 0;

	if (!exclude) {
		for (p = packed_git; p; p = p->next) {
			struct pack_entry e;
			if (find_pack_entry_one(sha1, &e, p)) {
				if (incremental)
					return 0;
				if (local && !p->pack_local)
					return 0;
				if (!found_pack) {
					found_offset = e.offset;
					found_pack = e.p;
				}
			}
		}
	}
	if ((entry = locate_object_entry(sha1)) != NULL)
		goto already_added;

	if (idx >= nr_alloc) {
		unsigned int needed = (idx + 1024) * 3 / 2;
		objects = xrealloc(objects, needed * sizeof(*entry));
		nr_alloc = needed;
	}
	entry = objects + idx;
	nr_objects = idx + 1;
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->sha1, sha1, 20);
	entry->hash = hash;

	if (object_ix_hashsz * 3 <= nr_objects * 4)
		rehash_objects();
	else {
		ix = locate_object_entry_hash(entry->sha1);
		if (0 <= ix)
			die("internal error in object hashing.");
		object_ix[-1 - ix] = idx + 1;
	}
	status = 1;

 already_added:
	if (progress_update) {
		fprintf(stderr, "Counting objects...%d\r", nr_objects);
		progress_update = 0;
	}
	if (exclude)
		entry->preferred_base = 1;
	else {
		if (found_pack) {
			entry->in_pack = found_pack;
			entry->in_pack_offset = found_offset;
		}
	}
	return status;
}

struct pbase_tree_cache {
	unsigned char sha1[20];
	int ref;
	int temporary;
	void *tree_data;
	unsigned long tree_size;
};

static struct pbase_tree_cache *(pbase_tree_cache[256]);
static int pbase_tree_cache_ix(const unsigned char *sha1)
{
	return sha1[0] % ARRAY_SIZE(pbase_tree_cache);
}
static int pbase_tree_cache_ix_incr(int ix)
{
	return (ix+1) % ARRAY_SIZE(pbase_tree_cache);
}

static struct pbase_tree {
	struct pbase_tree *next;
	/* This is a phony "cache" entry; we are not
	 * going to evict it nor find it through _get()
	 * mechanism -- this is for the toplevel node that
	 * would almost always change with any commit.
	 */
	struct pbase_tree_cache pcache;
} *pbase_tree;

static struct pbase_tree_cache *pbase_tree_get(const unsigned char *sha1)
{
	struct pbase_tree_cache *ent, *nent;
	void *data;
	unsigned long size;
	char type[20];
	int neigh;
	int my_ix = pbase_tree_cache_ix(sha1);
	int available_ix = -1;

	/* pbase-tree-cache acts as a limited hashtable.
	 * your object will be found at your index or within a few
	 * slots after that slot if it is cached.
	 */
	for (neigh = 0; neigh < 8; neigh++) {
		ent = pbase_tree_cache[my_ix];
		if (ent && !memcmp(ent->sha1, sha1, 20)) {
			ent->ref++;
			return ent;
		}
		else if (((available_ix < 0) && (!ent || !ent->ref)) ||
			 ((0 <= available_ix) &&
			  (!ent && pbase_tree_cache[available_ix])))
			available_ix = my_ix;
		if (!ent)
			break;
		my_ix = pbase_tree_cache_ix_incr(my_ix);
	}

	/* Did not find one.  Either we got a bogus request or
	 * we need to read and perhaps cache.
	 */
	data = read_sha1_file(sha1, type, &size);
	if (!data)
		return NULL;
	if (strcmp(type, tree_type)) {
		free(data);
		return NULL;
	}

	/* We need to either cache or return a throwaway copy */

	if (available_ix < 0)
		ent = NULL;
	else {
		ent = pbase_tree_cache[available_ix];
		my_ix = available_ix;
	}

	if (!ent) {
		nent = xmalloc(sizeof(*nent));
		nent->temporary = (available_ix < 0);
	}
	else {
		/* evict and reuse */
		free(ent->tree_data);
		nent = ent;
	}
	memcpy(nent->sha1, sha1, 20);
	nent->tree_data = data;
	nent->tree_size = size;
	nent->ref = 1;
	if (!nent->temporary)
		pbase_tree_cache[my_ix] = nent;
	return nent;
}

static void pbase_tree_put(struct pbase_tree_cache *cache)
{
	if (!cache->temporary) {
		cache->ref--;
		return;
	}
	free(cache->tree_data);
	free(cache);
}

static int name_cmp_len(const char *name)
{
	int i;
	for (i = 0; name[i] && name[i] != '\n' && name[i] != '/'; i++)
		;
	return i;
}

static void add_pbase_object(struct tree_desc *tree,
			     struct name_path *up,
			     const char *name,
			     int cmplen)
{
	while (tree->size) {
		const unsigned char *sha1;
		const char *entry_name;
		int entry_len;
		unsigned mode;
		unsigned long size;
		char type[20];

		sha1 = tree_entry_extract(tree, &entry_name, &mode);
		update_tree_entry(tree);
		entry_len = strlen(entry_name);
		if (entry_len != cmplen ||
		    memcmp(entry_name, name, cmplen) ||
		    !has_sha1_file(sha1) ||
		    sha1_object_info(sha1, type, &size))
			continue;
		if (name[cmplen] != '/') {
			unsigned hash = name_hash(up, name);
			add_object_entry(sha1, hash, 1);
			return;
		}
		if (!strcmp(type, tree_type)) {
			struct tree_desc sub;
			struct name_path me;
			struct pbase_tree_cache *tree;
			const char *down = name+cmplen+1;
			int downlen = name_cmp_len(down);

			tree = pbase_tree_get(sha1);
			if (!tree)
				return;
			sub.buf = tree->tree_data;
			sub.size = tree->tree_size;

			me.up = up;
			me.elem = entry_name;
			me.len = entry_len;
			add_pbase_object(&sub, &me, down, downlen);
			pbase_tree_put(tree);
		}
	}
}

static unsigned *done_pbase_paths;
static int done_pbase_paths_num;
static int done_pbase_paths_alloc;
static int done_pbase_path_pos(unsigned hash)
{
	int lo = 0;
	int hi = done_pbase_paths_num;
	while (lo < hi) {
		int mi = (hi + lo) / 2;
		if (done_pbase_paths[mi] == hash)
			return mi;
		if (done_pbase_paths[mi] < hash)
			hi = mi;
		else
			lo = mi + 1;
	}
	return -lo-1;
}

static int check_pbase_path(unsigned hash)
{
	int pos = (!done_pbase_paths) ? -1 : done_pbase_path_pos(hash);
	if (0 <= pos)
		return 1;
	pos = -pos - 1;
	if (done_pbase_paths_alloc <= done_pbase_paths_num) {
		done_pbase_paths_alloc = alloc_nr(done_pbase_paths_alloc);
		done_pbase_paths = xrealloc(done_pbase_paths,
					    done_pbase_paths_alloc *
					    sizeof(unsigned));
	}
	done_pbase_paths_num++;
	if (pos < done_pbase_paths_num)
		memmove(done_pbase_paths + pos + 1,
			done_pbase_paths + pos,
			(done_pbase_paths_num - pos - 1) * sizeof(unsigned));
	done_pbase_paths[pos] = hash;
	return 0;
}

static void add_preferred_base_object(char *name, unsigned hash)
{
	struct pbase_tree *it;
	int cmplen = name_cmp_len(name);

	if (check_pbase_path(hash))
		return;

	for (it = pbase_tree; it; it = it->next) {
		if (cmplen == 0) {
			hash = name_hash(NULL, "");
			add_object_entry(it->pcache.sha1, hash, 1);
		}
		else {
			struct tree_desc tree;
			tree.buf = it->pcache.tree_data;
			tree.size = it->pcache.tree_size;
			add_pbase_object(&tree, NULL, name, cmplen);
		}
	}
}

static void add_preferred_base(unsigned char *sha1)
{
	struct pbase_tree *it;
	void *data;
	unsigned long size;
	unsigned char tree_sha1[20];

	data = read_object_with_reference(sha1, tree_type, &size, tree_sha1);
	if (!data)
		return;

	for (it = pbase_tree; it; it = it->next) {
		if (!memcmp(it->pcache.sha1, tree_sha1, 20)) {
			free(data);
			return;
		}
	}

	it = xcalloc(1, sizeof(*it));
	it->next = pbase_tree;
	pbase_tree = it;

	memcpy(it->pcache.sha1, tree_sha1, 20);
	it->pcache.tree_data = data;
	it->pcache.tree_size = size;
}

static void check_object(struct object_entry *entry)
{
	char type[20];

	if (entry->in_pack && !entry->preferred_base) {
		unsigned char base[20];
		unsigned long size;
		struct object_entry *base_entry;

		/* We want in_pack_type even if we do not reuse delta.
		 * There is no point not reusing non-delta representations.
		 */
		check_reuse_pack_delta(entry->in_pack,
				       entry->in_pack_offset,
				       base, &size,
				       &entry->in_pack_type);

		/* Check if it is delta, and the base is also an object
		 * we are going to pack.  If so we will reuse the existing
		 * delta.
		 */
		if (!no_reuse_delta &&
		    entry->in_pack_type == OBJ_DELTA &&
		    (base_entry = locate_object_entry(base)) &&
		    (!base_entry->preferred_base)) {

			/* Depth value does not matter - find_deltas()
			 * will never consider reused delta as the
			 * base object to deltify other objects
			 * against, in order to avoid circular deltas.
			 */

			/* uncompressed size of the delta data */
			entry->size = entry->delta_size = size;
			entry->delta = base_entry;
			entry->type = OBJ_DELTA;

			entry->delta_sibling = base_entry->delta_child;
			base_entry->delta_child = entry;

			return;
		}
		/* Otherwise we would do the usual */
	}

	if (sha1_object_info(entry->sha1, type, &entry->size))
		die("unable to get type of object %s",
		    sha1_to_hex(entry->sha1));

	if (!strcmp(type, commit_type)) {
		entry->type = OBJ_COMMIT;
	} else if (!strcmp(type, tree_type)) {
		entry->type = OBJ_TREE;
	} else if (!strcmp(type, blob_type)) {
		entry->type = OBJ_BLOB;
	} else if (!strcmp(type, tag_type)) {
		entry->type = OBJ_TAG;
	} else
		die("unable to pack object %s of type %s",
		    sha1_to_hex(entry->sha1), type);
}

static unsigned int check_delta_limit(struct object_entry *me, unsigned int n)
{
	struct object_entry *child = me->delta_child;
	unsigned int m = n;
	while (child) {
		unsigned int c = check_delta_limit(child, n + 1);
		if (m < c)
			m = c;
		child = child->delta_sibling;
	}
	return m;
}

static void get_object_details(void)
{
	int i;
	struct object_entry *entry;

	prepare_pack_ix();
	for (i = 0, entry = objects; i < nr_objects; i++, entry++)
		check_object(entry);

	if (nr_objects == nr_result) {
		/*
		 * Depth of objects that depend on the entry -- this
		 * is subtracted from depth-max to break too deep
		 * delta chain because of delta data reusing.
		 * However, we loosen this restriction when we know we
		 * are creating a thin pack -- it will have to be
		 * expanded on the other end anyway, so do not
		 * artificially cut the delta chain and let it go as
		 * deep as it wants.
		 */
		for (i = 0, entry = objects; i < nr_objects; i++, entry++)
			if (!entry->delta && entry->delta_child)
				entry->delta_limit =
					check_delta_limit(entry, 1);
	}
}

typedef int (*entry_sort_t)(const struct object_entry *, const struct object_entry *);

static entry_sort_t current_sort;

static int sort_comparator(const void *_a, const void *_b)
{
	struct object_entry *a = *(struct object_entry **)_a;
	struct object_entry *b = *(struct object_entry **)_b;
	return current_sort(a,b);
}

static struct object_entry **create_sorted_list(entry_sort_t sort)
{
	struct object_entry **list = xmalloc(nr_objects * sizeof(struct object_entry *));
	int i;

	for (i = 0; i < nr_objects; i++)
		list[i] = objects + i;
	current_sort = sort;
	qsort(list, nr_objects, sizeof(struct object_entry *), sort_comparator);
	return list;
}

static int sha1_sort(const struct object_entry *a, const struct object_entry *b)
{
	return memcmp(a->sha1, b->sha1, 20);
}

static struct object_entry **create_final_object_list(void)
{
	struct object_entry **list;
	int i, j;

	for (i = nr_result = 0; i < nr_objects; i++)
		if (!objects[i].preferred_base)
			nr_result++;
	list = xmalloc(nr_result * sizeof(struct object_entry *));
	for (i = j = 0; i < nr_objects; i++) {
		if (!objects[i].preferred_base)
			list[j++] = objects + i;
	}
	current_sort = sha1_sort;
	qsort(list, nr_result, sizeof(struct object_entry *), sort_comparator);
	return list;
}

static int type_size_sort(const struct object_entry *a, const struct object_entry *b)
{
	if (a->type < b->type)
		return -1;
	if (a->type > b->type)
		return 1;
	if (a->hash < b->hash)
		return -1;
	if (a->hash > b->hash)
		return 1;
	if (a->preferred_base < b->preferred_base)
		return -1;
	if (a->preferred_base > b->preferred_base)
		return 1;
	if (a->size < b->size)
		return -1;
	if (a->size > b->size)
		return 1;
	return a < b ? -1 : (a > b);
}

struct unpacked {
	struct object_entry *entry;
	void *data;
};

/*
 * We search for deltas _backwards_ in a list sorted by type and
 * by size, so that we see progressively smaller and smaller files.
 * That's because we prefer deltas to be from the bigger file
 * to the smaller - deletes are potentially cheaper, but perhaps
 * more importantly, the bigger file is likely the more recent
 * one.
 */
static int try_delta(struct unpacked *cur, struct unpacked *old, unsigned max_depth)
{
	struct object_entry *cur_entry = cur->entry;
	struct object_entry *old_entry = old->entry;
	unsigned long size, oldsize, delta_size, sizediff;
	long max_size;
	void *delta_buf;

	/* Don't bother doing diffs between different types */
	if (cur_entry->type != old_entry->type)
		return -1;

	/* We do not compute delta to *create* objects we are not
	 * going to pack.
	 */
	if (cur_entry->preferred_base)
		return -1;

	/* If the current object is at pack edge, take the depth the
	 * objects that depend on the current object into account --
	 * otherwise they would become too deep.
	 */
	if (cur_entry->delta_child) {
		if (max_depth <= cur_entry->delta_limit)
			return 0;
		max_depth -= cur_entry->delta_limit;
	}

	size = cur_entry->size;
	oldsize = old_entry->size;
	sizediff = oldsize > size ? oldsize - size : size - oldsize;

	if (size < 50)
		return -1;
	if (old_entry->depth >= max_depth)
		return 0;

	/*
	 * NOTE!
	 *
	 * We always delta from the bigger to the smaller, since that's
	 * more space-efficient (deletes don't have to say _what_ they
	 * delete).
	 */
	max_size = size / 2 - 20;
	if (cur_entry->delta)
		max_size = cur_entry->delta_size-1;
	if (sizediff >= max_size)
		return 0;
	delta_buf = diff_delta(old->data, oldsize,
			       cur->data, size, &delta_size, max_size);
	if (!delta_buf)
		return 0;
	cur_entry->delta = old_entry;
	cur_entry->delta_size = delta_size;
	cur_entry->depth = old_entry->depth + 1;
	free(delta_buf);
	return 0;
}

static void progress_interval(int signum)
{
	progress_update = 1;
}

static void find_deltas(struct object_entry **list, int window, int depth)
{
	int i, idx;
	unsigned int array_size = window * sizeof(struct unpacked);
	struct unpacked *array = xmalloc(array_size);
	unsigned processed = 0;
	unsigned last_percent = 999;

	memset(array, 0, array_size);
	i = nr_objects;
	idx = 0;
	if (progress)
		fprintf(stderr, "Deltifying %d objects.\n", nr_result);

	while (--i >= 0) {
		struct object_entry *entry = list[i];
		struct unpacked *n = array + idx;
		unsigned long size;
		char type[10];
		int j;

		if (!entry->preferred_base)
			processed++;

		if (progress) {
			unsigned percent = processed * 100 / nr_result;
			if (percent != last_percent || progress_update) {
				fprintf(stderr, "%4u%% (%u/%u) done\r",
					percent, processed, nr_result);
				progress_update = 0;
				last_percent = percent;
			}
		}

		if (entry->delta)
			/* This happens if we decided to reuse existing
			 * delta from a pack.  "!no_reuse_delta &&" is implied.
			 */
			continue;

		free(n->data);
		n->entry = entry;
		n->data = read_sha1_file(entry->sha1, type, &size);
		if (size != entry->size)
			die("object %s inconsistent object length (%lu vs %lu)", sha1_to_hex(entry->sha1), size, entry->size);

		j = window;
		while (--j > 0) {
			unsigned int other_idx = idx + j;
			struct unpacked *m;
			if (other_idx >= window)
				other_idx -= window;
			m = array + other_idx;
			if (!m->entry)
				break;
			if (try_delta(n, m, depth) < 0)
				break;
		}
#if 0
		/* if we made n a delta, and if n is already at max
		 * depth, leaving it in the window is pointless.  we
		 * should evict it first.
		 * ... in theory only; somehow this makes things worse.
		 */
		if (entry->delta && depth <= entry->depth)
			continue;
#endif
		idx++;
		if (idx >= window)
			idx = 0;
	}

	if (progress)
		fputc('\n', stderr);

	for (i = 0; i < window; ++i)
		free(array[i].data);
	free(array);
}

static void prepare_pack(int window, int depth)
{
	get_object_details();
	sorted_by_type = create_sorted_list(type_size_sort);
	if (window && depth)
		find_deltas(sorted_by_type, window+1, depth);
}

static int reuse_cached_pack(unsigned char *sha1, int pack_to_stdout)
{
	static const char cache[] = "pack-cache/pack-%s.%s";
	char *cached_pack, *cached_idx;
	int ifd, ofd, ifd_ix = -1;

	cached_pack = git_path(cache, sha1_to_hex(sha1), "pack");
	ifd = open(cached_pack, O_RDONLY);
	if (ifd < 0)
		return 0;

	if (!pack_to_stdout) {
		cached_idx = git_path(cache, sha1_to_hex(sha1), "idx");
		ifd_ix = open(cached_idx, O_RDONLY);
		if (ifd_ix < 0) {
			close(ifd);
			return 0;
		}
	}

	if (progress)
		fprintf(stderr, "Reusing %d objects pack %s\n", nr_objects,
			sha1_to_hex(sha1));

	if (pack_to_stdout) {
		if (copy_fd(ifd, 1))
			exit(1);
		close(ifd);
	}
	else {
		char name[PATH_MAX];
		snprintf(name, sizeof(name),
			 "%s-%s.%s", base_name, sha1_to_hex(sha1), "pack");
		ofd = open(name, O_CREAT | O_EXCL | O_WRONLY, 0666);
		if (ofd < 0)
			die("unable to open %s (%s)", name, strerror(errno));
		if (copy_fd(ifd, ofd))
			exit(1);
		close(ifd);

		snprintf(name, sizeof(name),
			 "%s-%s.%s", base_name, sha1_to_hex(sha1), "idx");
		ofd = open(name, O_CREAT | O_EXCL | O_WRONLY, 0666);
		if (ofd < 0)
			die("unable to open %s (%s)", name, strerror(errno));
		if (copy_fd(ifd_ix, ofd))
			exit(1);
		close(ifd_ix);
		puts(sha1_to_hex(sha1));
	}

	return 1;
}

static void setup_progress_signal(void)
{
	struct sigaction sa;
	struct itimerval v;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = progress_interval;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &sa, NULL);

	v.it_interval.tv_sec = 1;
	v.it_interval.tv_usec = 0;
	v.it_value = v.it_interval;
	setitimer(ITIMER_REAL, &v, NULL);
}

int main(int argc, char **argv)
{
	SHA_CTX ctx;
	char line[40 + 1 + PATH_MAX + 2];
	int window = 10, depth = 10, pack_to_stdout = 0;
	struct object_entry **list;
	int num_preferred_base = 0;
	int i;

	setup_git_directory();

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (*arg == '-') {
			if (!strcmp("--non-empty", arg)) {
				non_empty = 1;
				continue;
			}
			if (!strcmp("--local", arg)) {
				local = 1;
				continue;
			}
			if (!strcmp("--incremental", arg)) {
				incremental = 1;
				continue;
			}
			if (!strncmp("--window=", arg, 9)) {
				char *end;
				window = strtoul(arg+9, &end, 0);
				if (!arg[9] || *end)
					usage(pack_usage);
				continue;
			}
			if (!strncmp("--depth=", arg, 8)) {
				char *end;
				depth = strtoul(arg+8, &end, 0);
				if (!arg[8] || *end)
					usage(pack_usage);
				continue;
			}
			if (!strcmp("-q", arg)) {
				progress = 0;
				continue;
			}
			if (!strcmp("--no-reuse-delta", arg)) {
				no_reuse_delta = 1;
				continue;
			}
			if (!strcmp("--stdout", arg)) {
				pack_to_stdout = 1;
				continue;
			}
			usage(pack_usage);
		}
		if (base_name)
			usage(pack_usage);
		base_name = arg;
	}

	if (pack_to_stdout != !base_name)
		usage(pack_usage);

	prepare_packed_git();

	if (progress) {
		fprintf(stderr, "Generating pack...\n");
		setup_progress_signal();
	}

	for (;;) {
		unsigned char sha1[20];
		unsigned hash;

		if (!fgets(line, sizeof(line), stdin)) {
			if (feof(stdin))
				break;
			if (!ferror(stdin))
				die("fgets returned NULL, not EOF, not error!");
			if (errno != EINTR)
				die("fgets: %s", strerror(errno));
			clearerr(stdin);
			continue;
		}

		if (line[0] == '-') {
			if (get_sha1_hex(line+1, sha1))
				die("expected edge sha1, got garbage:\n %s",
				    line+1);
			if (num_preferred_base++ < window)
				add_preferred_base(sha1);
			continue;
		}
		if (get_sha1_hex(line, sha1))
			die("expected sha1, got garbage:\n %s", line);
		hash = name_hash(NULL, line+41);
		add_preferred_base_object(line+41, hash);
		add_object_entry(sha1, hash, 0);
	}
	if (progress)
		fprintf(stderr, "Done counting %d objects.\n", nr_objects);
	sorted_by_sha = create_final_object_list();
	if (non_empty && !nr_result)
		return 0;

	SHA1_Init(&ctx);
	list = sorted_by_sha;
	for (i = 0; i < nr_result; i++) {
		struct object_entry *entry = *list++;
		SHA1_Update(&ctx, entry->sha1, 20);
	}
	SHA1_Final(object_list_sha1, &ctx);
	if (progress && (nr_objects != nr_result))
		fprintf(stderr, "Result has %d objects.\n", nr_result);

	if (reuse_cached_pack(object_list_sha1, pack_to_stdout))
		;
	else {
		if (nr_result)
			prepare_pack(window, depth);
		if (progress && pack_to_stdout) {
			/* the other end usually displays progress itself */
			struct itimerval v = {{0,},};
			setitimer(ITIMER_REAL, &v, NULL);
			signal(SIGALRM, SIG_IGN );
			progress_update = 0;
		}
		write_pack_file();
		if (!pack_to_stdout) {
			write_index_file();
			puts(sha1_to_hex(object_list_sha1));
		}
	}
	if (progress)
		fprintf(stderr, "Total %d, written %d (delta %d), reused %d (delta %d)\n",
			nr_result, written, written_delta, reused, reused_delta);
	return 0;
}
