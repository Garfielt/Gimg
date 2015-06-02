#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <sys/sendfile.h>


#include <pcre.h>
#include <wand/MagickWand.h>

#include <evhtp.h>

#define SERVER_IP "your_ip_here"
#define SERVER_DOMAIN "your_domain_here"
#define SERVER_NAME "imgsrv/0.1"
#define SERVER_ROOT "./img"
#define SENDFILE 0
#define DEBUG 0


const char *error;
int erroffset;

pcre *re;
MagickWand *mwd;

void LOG_PRINT(const char *fmt, ... ) {
	if(DEBUG){
		va_list arg_ptr;
		va_start(arg_ptr, fmt);
		char buf[1024];
		vsprintf(buf, fmt, arg_ptr);
		printf("%s \n", buf);
	}
}

static const struct table_entry {
	const char *extension;
	const char *content_type;
} content_type_table[] = {
	{ "txt", "text/plain" },
	{ "html", "text/html" },
	{ "htm", "text/htm" },
	{ "css", "text/css" },
	{ "gif", "image/gif" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "png", "image/png" },
	{ "js", "application/javascript" },
	{ NULL, NULL },
};

static const char *
content_type(const char *path)
{
	const char *last_period, *extension;
	const struct table_entry *ent;
	last_period = strrchr(path, '.');
	if (!last_period || strchr(last_period, '/'))
		goto not_found; /* no exension */
	extension = last_period + 1;
	for (ent = &content_type_table[0]; ent->extension; ++ent) {
		if (!evutil_ascii_strcasecmp(ent->extension, extension))
			return ent->content_type;
	}
    not_found:
	    return "application/misc";
}

size_t                          /* O - Length of string */
str_lcat(char       *dst,       /* O - Destination string */
        const char  *src,       /* I - Source string */
        size_t      size)       /* I - Size of destination string buffer */
{
    size_t    srclen;           /* Length of source string */
    size_t    dstlen;           /* Length of destination string */
    /*
    * Figure out how much room is left...
    */
    
    dstlen = strlen(dst);
    size   -= dstlen + 1;
    
    if (!size)
      return (dstlen);          /* No room, return immediately... */
    
    /*
    * Figure out how much room is needed...
    */
    
    srclen = strlen(src);
    /*
    * Copy the appropriate amount...
    */
    
    if (srclen > size)
      srclen = size;
    
    memcpy(dst + dstlen, src, srclen);
    dst[dstlen + srclen] = '\0';
    
    return (dstlen + srclen);
}

/*
 * '_cups_strlcpy()' - Safely copy two strings.
 */
size_t                              /* O - Length of string */
str_lcpy(char           *dst,       /* O - Destination string */
        const char      *src,       /* I - Source string */
        size_t          size)       /* I - Size of destination string buffer */
{
    size_t    srclen;               /* Length of source string */
    /*
    * Figure out how much room is needed...
    */
    size --;
    srclen = strlen(src);
    
    /*
    * Copy the appropriate amount...
    */
    if (srclen > size)
      srclen = size;
    
    memcpy(dst, src, srclen);
    dst[srclen] = '\0';
    
    return (srclen);
}

int is_file(const char *filename)
{
    struct stat st;
    if(stat(filename, &st)<0)
    {
        LOG_PRINT("File[%s] is Not Existed!", filename);
        return -1;
    }
    if(S_ISREG(st.st_mode))
    {
        LOG_PRINT("File[%s] is A File.", filename);
        return 1;
    }
    return -1;
}

int is_dir(const char *path)
{
    struct stat st;
    if(stat(path, &st)<0)
    {
        LOG_PRINT("Path[%s] is Not Existed!", path);
        return -1;
    }
    if(S_ISDIR(st.st_mode))
    {
        LOG_PRINT("Path[%s] is A Dir.", path);
        return 1;
    }
    else
        return -1;
}

int mk_dir(const char *path)
{
    if(access(path, 0) == -1)
    {
        int status = mkdir(path, 0755);
        if(status == -1)
        {
            LOG_PRINT("mkdir[%s] Failed!", path);
            return -1;
        }
        LOG_PRINT("mkdir[%s] sucessfully!", path);
        return 1;
    }
    else
    {
        LOG_PRINT("Path[%s] is Existed!", path);
        return -1;
    }
}

int mk_dirs(const char *dir)
{
    char tmp[256];
    str_lcpy(tmp, dir, sizeof(tmp));
    int i, len = strlen(tmp);
    if(tmp[len-1] != '/')
        str_lcat(tmp, "/", sizeof(tmp));

    len = strlen(tmp);

    for(i=1; i<len; i++)
    {
        if(tmp[i] == '/')
        {
            tmp[i] = 0;
            if(access(tmp, 0) != 0)
            {
                if(mkdir(tmp, 0755) == -1)
                {
                    fprintf(stderr, "mk_dirs: tmp=%s", tmp);
                    return -1;
                }
            }
            tmp[i] = '/';
        }
    }
    return 1;
} 

int mk_dirf(const char *filename)
{
    int ret = 1;
    if(access(filename, 0) == 0)
        return ret;
    size_t len = strlen(filename);
    char str[256];
    str_lcpy(str, filename, len);
    str[len] = '\0';
    char *end = str;
    char *start = strchr(end, '/');
    while(start){
        end = start + 1;
        start = strchr(end, '/');
    }
    
    if(end != str)
    {
        str[end-str] = '\0';
        ret = mk_dirs(str);
    }
    return ret;
}

size_t gen_path(const char * filename)
{
    size_t ret = 0;
    int len = strlen(filename);
    size_t i;
    for(i=1; i<len; i++)
    {
        if(filename[i] == '/')
        {
            ret = i + 1;
        }
    }
    return ret;
}


int save_img(const char *buff, const size_t len, const char *save_name)
{ 
    int result = -1;
    LOG_PRINT("Start to Storage the New Image...");
    int fd = -1;
    int wlen = 0;

    if((fd = open(save_name, O_WRONLY | O_TRUNC | O_CREAT, 00644)) < 0)
    {
        LOG_PRINT("fd(%s) open failed!", save_name);
        goto done;
    }

    if(flock(fd, LOCK_EX | LOCK_NB) == -1)
    {
        LOG_PRINT("This fd is Locked by Other thread.");
        goto done;
    }

    wlen = write(fd, buff, len);
    if(wlen == -1)
    {
        LOG_PRINT("write(%s) failed!", save_name);
        goto done;
    }
    else if(wlen < len)
    {
        LOG_PRINT("Only part of [%s] is been writed.", save_name);
        goto done;
    }
    flock(fd, LOCK_UN | LOCK_NB);
    LOG_PRINT("Image [%s] Write Successfully!", save_name);
    result = 1;

done:
    if(fd != -1)
        close(fd);
    return result;
}

static void
backend_cb(evhtp_request_t * backend_req, void * arg) {
	LOG_PRINT("Backend Callback!");
    evhtp_request_t * frontend_req = (evhtp_request_t *)arg;
	LOG_PRINT("Stat Code: %d ", backend_req->status);
    //evbuffer_prepend_buffer(frontend_req->buffer_out, backend_req->buffer_in);
    //evhtp_headers_add_headers(frontend_req->headers_out, backend_req->headers_in);

    switch(backend_req->status)
    {
        case EVHTP_RES_200:
        {
            char save_path[256];
            char whole_path[256];
			struct evbuffer* buffer_in = backend_req->buffer_in;
            
            snprintf(whole_path, 256, "%s%s", SERVER_ROOT, frontend_req->uri->path->full);
            size_t len = evbuffer_get_length(buffer_in);
            char *tmp = malloc(len+1);
            memcpy(tmp, evbuffer_pullup(buffer_in, -1), len);
            tmp[len] = '\0';
            LOG_PRINT("Received Size: %zu", len);
			LOG_PRINT("CONTENT: %s", tmp);
            size_t plen = gen_path(whole_path);
            strncpy(save_path, whole_path, plen);
            save_path[plen] = '\0';
            //snprintf(save_path, 256, "%s", gen_path(whole_path));
            LOG_PRINT("Saved dir is: %s ", save_path);
            if(is_dir(save_path) == -1)
            {
                if(mk_dirs(save_path) == -1)
                {
                    LOG_PRINT("Create save_path: [%s] Failed!", save_path);
                }
            }
            save_img(tmp, len, whole_path);
            const char *content_type = evhtp_header_find(backend_req->headers_in, "Content-Type");
            LOG_PRINT("Content-Type:%s", content_type);
            //evbuffer_prepend(frontend_req->buffer_out, backend_req->buffer_in, evbuffer_get_length(backend_req->buffer_in));
            evbuffer_add(frontend_req->buffer_out, tmp, len);
            free(tmp);
            evhtp_headers_add_header(frontend_req->headers_out, evhtp_header_new("Server", SERVER_NAME, 0, 1));
	        evhtp_headers_add_header(frontend_req->headers_out, evhtp_header_new("Content-Type", content_type, 0, 0));
            evhtp_headers_add_header(frontend_req->headers_out, evhtp_header_new("Cache-Control", "max-age=7776000", 1, 1));
            evhtp_send_reply(frontend_req, EVHTP_RES_OK);
            evhtp_request_resume(frontend_req);
            break;
        }
        case EVHTP_RES_MOVEDPERM:
            LOG_PRINT("%s", "Uri moved permanently");
            evhtp_send_reply(frontend_req, EVHTP_RES_MOVEDPERM);
            evhtp_request_resume(frontend_req);
            break;
            
        default:
            evhtp_send_reply(frontend_req, EVHTP_RES_NOTFOUND);
            evhtp_request_resume(frontend_req);
    }

    evhtp_send_reply(frontend_req, EVHTP_RES_OK);
    evhtp_request_resume(frontend_req);
}


int
make_request(evbase_t         * evbase,
             evthr_t          * evthr,
             const char * const path,
             void             * arg) {
    evhtp_connection_t * conn;
    evhtp_request_t    * request;

    LOG_PRINT("Backend Request URL: [%s]", path);

    conn         = evhtp_connection_new(evbase, SERVER_IP, 80);
    conn->thread = evthr;
    request      = evhtp_request_new(backend_cb, arg);

    evhtp_headers_add_header(request->headers_out, evhtp_header_new("Host", SERVER_DOMAIN, 0, 0));
    evhtp_headers_add_header(request->headers_out, evhtp_header_new("User-Agent", "libevhtp", 0, 0));
    evhtp_headers_add_header(request->headers_out, evhtp_header_new("Connection", "close", 0, 0));

    printf("Making backend request...\n");
    evhtp_make_request(conn, request, htp_method_GET, path);
    printf("Ok.\n");

    return 0;
}

static void
frontend_cb(evhtp_request_t * req, void * arg) {
    int * aux;
    int   thr;

	const char *uri;
	char whole_path[512];
	char original_path[512];

	struct stat f_stat;
	struct tm filetime;
	char etag[30];
	size_t len = 0;
	int result = -1;

    int fd = -1;
	char *buff = NULL;   


    //thread
    aux = (int *)evthr_get_aux(req->conn->thread);
    thr = *aux;
	evthr_t *thread = get_request_thr(req);
    thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);
    LOG_PRINT("Received Request on thread %d... ", thr);

	evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
    struct sockaddr *saddr = ev_conn->saddr;
    struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
    char address[16];
    strncpy(address, inet_ntoa(ss->sin_addr), 16);

	LOG_PRINT("A Request from %s", address);

    int req_method = evhtp_request_get_method(req);
    if(req_method >= 16)
        req_method = 16;
    LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
    if(strcmp(method_strmap[req_method], "GET") != 0){
        LOG_PRINT("Request Method Not Support.");
        LOG_PRINT("%s refuse method", address);
        goto err;
    }
    
    uri = req->uri->path->full;
	LOG_PRINT("Request uri: [%s]",  uri);

	if(strlen(uri) == 1 && uri[0] == '/')
    {
		LOG_PRINT("Request Root: [/]");
        evbuffer_add_printf(req->buffer_out, "<html>\n<body>\n<h1>\nWelcome To img World!</h1>\n</body>\n</html>\n");
        evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
        evhtp_send_reply(req, EVHTP_RES_OK);
        goto done;
    }

    if(strstr(uri, "favicon.ico"))
    {
        LOG_PRINT("Request: [favicon.ico]");
        goto forbidden;
    }

	if (strstr(uri, ".."))
    {
        LOG_PRINT("Request upper dir, Forbidden!");
		goto forbidden;
    }

	snprintf(whole_path, 512, "%s%s", SERVER_ROOT, uri);
	LOG_PRINT("Request whole_path: [%s]", whole_path);

	if(is_file(whole_path) == -1){
        LOG_PRINT("Whole_path Image is not existed!");
		LOG_PRINT("Begin to use PCRE Regez!");
		
		const char *ori_path;
		const char *width, *height;
		int rwidth, rheight;
		const char *extension;

		char rext[10];
		int oveccount = 18;
		int ovector[oveccount];
		int rc;
		rc = pcre_exec(re, NULL, whole_path, strlen(whole_path), 0, 0, ovector, oveccount);
		if (rc < 0) {
			if (rc == PCRE_ERROR_NOMATCH) {
				LOG_PRINT("PCRE not matched");
			}else {
				LOG_PRINT("Matching error: %d", rc);
			}
			snprintf(original_path, 512, "%s", whole_path);
			snprintf(rext, 10, "jpg");
		}else{
			
			pcre_get_substring(whole_path, ovector, rc, 1, &ori_path);
			pcre_get_substring(whole_path, ovector, rc, 2, &width);
			pcre_get_substring(whole_path, ovector, rc, 3, &height);
			pcre_get_substring(whole_path, ovector, rc, 4, &extension);
			LOG_PRINT("Matched: %s %sx%s %s", ori_path, width, height, extension);
			snprintf(original_path, 512, "%s", ori_path);
			rwidth = (width) ? atoi(width) : 0;
			rheight = (height) ? atoi(height) : 0;
			snprintf(rext, 10, "%s", extension);

			pcre_free_substring(ori_path);
			pcre_free_substring(width);
			pcre_free_substring(height);
			pcre_free_substring(extension);
		}

		if(is_file(original_path) == -1){
			LOG_PRINT("Original_path Image is not existed!");
			LOG_PRINT("Pause frontend callback!");
			evhtp_request_pause(req);
			LOG_PRINT("Make backend Request!");
			make_request(evthr_get_base(req->conn->thread),
						 req->conn->thread,
						 req->uri->path->full,
						 req);
			return;
		}

		LOG_PRINT("Change Resolution: [%s]", original_path);
		MagickBooleanType ret = MagickReadImage(mwd, original_path);
		MagickSizeType size = MagickGetImageSize(mwd);
		MagickResetIterator(mwd);
		while (MagickNextImage(mwd) != MagickFalse)
			MagickResizeImage(mwd, rwidth, rheight, LanczosFilter, 1.0);
		ret = MagickSetImageFormat(mwd, rext);
        if (ret != MagickTrue)
			goto err;
		char *new_buff = (char *)MagickWriteImageBlob(mwd, &len);
		result = evbuffer_add(req->buffer_out, new_buff, len);
		if(result == 2)
			goto err;
		LOG_PRINT("Save New Resolution file: [%s]", whole_path);
		save_img(new_buff, len, whole_path);
		free(new_buff);
    }

	if (!stat(whole_path, &f_stat)){
		filetime = *localtime(&f_stat.st_atime);
		strftime(etag, sizeof(etag), "%Y%m%d%H%M%S", &filetime);
		//sprintf(etag, "%Y%m%d%H%M%S", &filetime);
		LOG_PRINT("Etag: %s", etag);
	}

	const char *etag_var = evhtp_header_find(req->headers_in, "If-None-Match");
	LOG_PRINT("Etag_var:%s", etag_var);
	if(etag_var == NULL){
		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Etag", etag, 0, 1));
	}else{
		if(strncmp(etag, etag_var, 32) == 0){
			LOG_PRINT("Etag not modify, Return 304");
			evhtp_send_reply(req, EVHTP_RES_NOTMOD);
			goto done;
		}else{
			LOG_PRINT("Add Etag header");
			evhtp_headers_add_header(req->headers_out, evhtp_header_new("Etag", etag, 0, 1));
		}
	}

	if((fd = open(whole_path, O_RDONLY)) == -1) {
		LOG_PRINT("Open whole_path [%s] error", whole_path);
	}else{
		fstat(fd, &f_stat);
		size_t rlen = 0;
		len = f_stat.st_size;
		if(len <= 0){
			LOG_PRINT("Whole_path is Empty.");
			goto err;
		}
		if (SENDFILE) {
			result = evbuffer_add_file(req->buffer_out, fd, 0, len);
			if(result == -1)
				goto err;
		}else{
			if((buff = (char *)malloc(len)) == NULL){
				LOG_PRINT("Whole_path buff Malloc Failed!");
				goto err;
			}
			if((rlen = read(fd, buff, len)) == -1){
				LOG_PRINT("Whole_path Read Failed");
				goto err;
			}else if(rlen < len){
				LOG_PRINT("Whole_path Read Not Compeletly.");
				goto err;
			}
			result = evbuffer_add(req->buffer_out, buff, len);
			if(result == 2)
				goto err;
		}

		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", content_type(whole_path), 0, 0));
		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Cache-Control", "max-age=7776000", 1, 1));
		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", SERVER_NAME, 0, 1));
		evhtp_send_reply(req, EVHTP_RES_OK);
		goto done;
	}
	forbidden:
		LOG_PRINT("Forbidden~~~~~~~~~~~~~~~");
		evbuffer_add_printf(req->buffer_out, "<html><body><h1>403 Forbidden!</h1></body></html>"); 
		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", SERVER_NAME, 0, 1));
		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
		evhtp_send_reply(req, EVHTP_RES_FORBIDDEN);
		goto done;
	err:
		LOG_PRINT("Error~~~~~~~~~~~~~~~");
		evbuffer_add_printf(req->buffer_out, "<html><body><h1>404 Not Found!</h1></body></html>");
		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", SERVER_NAME, 0, 1));
		evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
		evhtp_send_reply(req, EVHTP_RES_NOTFOUND);
	done:
		LOG_PRINT("Done! Free~~~~~~~~~~~~~~~");
		if(fd != -1 && SENDFILE == 0)
			close(fd);
		free(buff);
}

void
sigterm_cb(int fd, short event, void * arg) {
    evbase_t     * evbase = (evbase_t *)arg;
    struct timeval tv     = { .tv_usec = 100000, .tv_sec = 0 }; /* 100 ms */

    event_base_loopexit(evbase, &tv);
}

void
init_thread_cb(evhtp_t * htp, evthr_t * thr, void * arg) {
    static int aux = 0;

    LOG_PRINT("Spinning up a thread: %d", ++aux);
    evthr_set_aux(thr, &aux);
}

int
main(int argc, char ** argv) {
    //struct event *ev_sigterm;
	char pattern[] = "(.+)_(\\d+)x(\\d+).(.+)";
	int i, sret;
	for(i=1; i<argc; i++)
    {
        if(strcmp(argv[i], "-d") == 0){
            if(daemon(1, 1) < 0)
			{
				fprintf(stderr, "Create daemon failed!\n");
				return -1;
			}
			else
			{
				fprintf(stdout, "imgsrv 0.1\n");
				fprintf(stdout, "Copyright (c) 2014 blog.iscsky.net\n");
				fprintf(stderr, "\n");
			}
        }
    }

	MagickCoreGenesis((char *) NULL, MagickFalse);
	mwd = NewMagickWand();

	re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
	if (re == NULL) {
		fprintf(stderr, "PCRE compilation telephone failed at offset %d: %s\n", erroffset,  error);
		return -1;
	}
	
    evbase_t    * evbase  = event_base_new();
	struct event_base * httpbase = event_base_new();
    evhtp_t     * evhtp   = evhtp_new(evbase, NULL);

    evhtp_set_gencb(evhtp, frontend_cb, NULL);

#if 1
    evhtp_use_threads(evhtp, init_thread_cb, 2, NULL);
#endif
	evhtp_set_max_keepalive_requests(evhtp, 1);
    sret = evhtp_bind_socket(evhtp, "0.0.0.0", 80, 1024);
	if(sret < 0){
		fprintf(stderr, "Bind Socket failed!\n");
		return -1;
	}
    event_base_loop(evbase, 0);
	if(mwd != NULL)
		DestroyMagickWand(mwd);
	MagickWandTerminus();
	evhtp_unbind_socket(evhtp);
    event_base_free(evbase);
    return 0;
}