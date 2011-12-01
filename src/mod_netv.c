#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#define PROJECT_DIR "/Users/smc/Sites/dev/luaed/projects/"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

/**
 * this is a netv for a lighttpd plugin
 *
 * just replaces every occurance of 'netv' by your plugin name
 *
 * e.g. in vim:
 *
 *   :%s/netv/myhandler/
 *
 */



/* plugin config for all request/connections */

typedef struct {
	array *match;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	buffer *match_buf;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

typedef struct {
	size_t foo;
} handler_ctx;

/*
static handler_ctx * handler_ctx_init() {
	handler_ctx * hctx;

	hctx = calloc(1, sizeof(*hctx));

	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {

	free(hctx);
}
*/

/* init the plugin data */
INIT_FUNC(mod_netv_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->match_buf = buffer_init();

	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_netv_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

			array_free(s->match);

			free(s);
		}
		free(p->config_storage);
	}

	buffer_free(p->match_buf);

	free(p);

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_netv_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "netv.array",             NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->match    = array_init();

		cv[0].destination = s->match;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}


static int
handle_lua_uri(server *srv, connection *con, char *uri)
{
    UNUSED(srv);
    UNUSED(con);
    UNUSED(uri);
    return HANDLER_GO_ON;
}

enum file_operation {
    PROJ_CREATE,    // create a new project
    PROJ_LIST,      // list all projects
    PROJ_DELETE,    // delete the project and all files
    PROJ_UNKNOWN,   // Who knows?
    FILE_LIST,      // list files in a project
    FILE_CREATE,    // Creating a new file
    FILE_FETCH,     // Fetch the contents of a file
    FILE_DELETE,    // Delete a file
    FILE_RENAME,    // Rename a file
    FILE_LINK,      // Hardlink a file between projects
    FILE_UNKNOWN,
};

const char *
op_to_str(enum file_operation op)
{
    if (op == PROJ_CREATE)
        return "PROJ_CREATE";
    if (op == PROJ_LIST)
        return "PROJ_LIST";
    if (op == PROJ_DELETE)
        return "PROJ_DELETE";
    if (op == PROJ_UNKNOWN)
        return "PROJ_UNKNWON";
    if (op == FILE_LIST)
        return "FILE_LIST";
    if (op == FILE_CREATE)
        return "FILE_CREATE";
    if (op == FILE_FETCH)
        return "FILE_FETCH";
    if (op == FILE_DELETE)
        return "FILE_DELETE";
    if (op == FILE_RENAME)
        return "FILE_RENAME";
    if (op == FILE_LINK)
        return "FILE_LINK";
    if (op == FILE_UNKNOWN)
        return "FILE_UNKNOWN";
    return "Please update op_to_str()";
}


/* Replace all instances of the character 'src' with 'dst' in string 'c' */
static int
strrep(char *c, char src, char dst)
{
    for(; *c; c++)
        if (*c == src)
            *c = dst;
    return 0;
}


static int
handle_file_uri(server *srv, connection *con, char *uri)
{
    char project_name[1024];
    char file_name[1024];
    char file2_name[1024];
    char *uri_tmp;
    enum file_operation op;
    buffer *b;

    bzero(project_name, sizeof(project_name));
    bzero(file_name, sizeof(file_name));
    bzero(file2_name, sizeof(file2_name));
    uri_tmp = uri;
    op = PROJ_UNKNOWN;
    con->file_started  = 1;
    con->file_finished = 1;

    if (!*uri)
        op = PROJ_LIST;
    else {
        char *slashes = strchr(uri, '/');
        int len;

        /*
         * If no slashes were found, or if it ends in a slash, treat it as
         * a "file list" operationn.
         */
        if (!slashes || !slashes[1]) {
            op = FILE_LIST;
            len = sizeof(project_name)-1;
            if (slashes && slashes-uri < len)
                len = slashes-uri;
            strncpy(project_name, uri, len);
        }

        /* It ends in a slash, followed by more text */
        else {
            len = sizeof(project_name)-1;
            if (slashes-uri < len)
                len = slashes-uri;
            strncpy(project_name, uri, len);

            /*
             * It contains an empty filename string, indicating it's an
             * operation on the project itself.
             */
            if (slashes[1] == '.') {
                slashes+=2;
                if (!strcmp(slashes, "create"))
                    op = PROJ_CREATE;
                else if (!strcmp(slashes, "delete"))
                    op = PROJ_DELETE;
                else
                    op = PROJ_UNKNOWN;
            }
            else {
                uri_tmp = slashes+1;
                slashes = strchr(uri_tmp, '/');

                /* A rename, delete, or link operation */
                if (slashes &&
                    !strncmp(slashes+1, "rename/", strlen("rename/"))) {

                    len = slashes-uri_tmp;
                    strncpy(file_name, uri_tmp, len);
                    uri_tmp = slashes+1+strlen("rename/");;
                    strcpy(file2_name, uri_tmp);
                    strrep(file2_name, '/', '\0');

                    op = FILE_RENAME;
                }
                else if (slashes &&
                         !strncmp(slashes+1, "link/", strlen("link/"))) {

                    len = slashes-uri_tmp;
                    strncpy(file_name, uri_tmp, len);
                    uri_tmp = slashes+1+strlen("link/");;
                    strcpy(file2_name, uri_tmp);
                    strrep(file2_name, '/', '\0');

                    op = FILE_LINK;
                }
                else if (slashes && !strcmp(slashes+1, "delete")) {
                    len = slashes-uri_tmp;
                    strncpy(file_name, uri_tmp, len);
                    op = FILE_DELETE;
                }
                else if (slashes) {
                    op = FILE_UNKNOWN;
                }
                else {
                    if (con->request.http_method == HTTP_METHOD_POST) {
                        op = FILE_CREATE;
                        strncpy(file_name, uri_tmp, sizeof(file_name)-1);
                    }
                    else {
                        op = FILE_FETCH;
                        strncpy(file_name, uri_tmp, sizeof(file_name)-1);
                    }
                }
            }
        }
    }

    strrep(project_name, '/', '\0');
    strrep(file_name, '/', '\0');
    strrep(file2_name, '/', '\0');

    if (strstr(project_name, "..")
     || strstr(file_name, "..")
     || strstr(file2_name, "..")) {
        con->http_status = 500;
        return HANDLER_FINISHED;
    }

    log_error_write(srv, __FILE__, __LINE__, "sssssssssds",
            "Raw URI:", uri,
            " project_name:", project_name,
            " file name:", file_name,
            " file2 name:", file2_name,
            " file operation:", op, op_to_str(op));

    if (op == PROJ_CREATE) {
        int res;
        char bfr[1024];

        bzero(bfr, sizeof(bfr));
        snprintf(bfr, sizeof(bfr)-1, "%s/%s", PROJECT_DIR, project_name);

        res = mkdir(bfr, 0755);
        if (-1 == res) {
            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(bfr, sizeof(bfr)-1,
                    "Unable to create project: %s", strerror(errno));
            buffer_copy_string(b, bfr);
            con->http_status = 500;
            return HANDLER_FINISHED;
        }
    }

    else if (op == PROJ_LIST) {
        DIR *proj_dir;
        struct dirent *de;

        proj_dir = opendir(PROJECT_DIR);
        if (!proj_dir) {
            con->http_status = 500;
            return HANDLER_FINISHED;
        }

        while ((de = readdir(proj_dir)) != NULL) {
            char entry[2048];

            /* Only accept files */
            if ((de->d_type != DT_DIR)) {
                continue;
            }
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
                continue;
            }

            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(entry, sizeof(entry)-1, "%s\n", de->d_name);
            buffer_copy_string(b, entry);
        }
        closedir(proj_dir);
    }

    else if (op == PROJ_DELETE) {
        struct dirent *de;
        DIR *proj_dir;
        char proj[2048];
        char bfr[1024];

        snprintf(proj, sizeof(proj)-1, "%s/%s", PROJECT_DIR, project_name);

        proj_dir = opendir(proj);
        if (!proj_dir) {
            con->http_status = 500;
            return HANDLER_FINISHED;
        }

        while ((de = readdir(proj_dir)) != NULL) {
            char entry[2048];

            /* Only accept files */
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            snprintf(entry, sizeof(entry)-1, "%s/%s/%s", PROJECT_DIR,
                    project_name, de->d_name);
            if (unlink(entry)) {
                b = chunkqueue_get_append_buffer(con->write_queue);
                snprintf(bfr, sizeof(bfr)-1,
                        "Unable to remove file from project: %s",
                        strerror(errno));
                buffer_copy_string(b, bfr);
                con->http_status = 500;
                return HANDLER_FINISHED;
            }
        }
        closedir(proj_dir);

        if (rmdir(proj) < 0) {
            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(bfr, sizeof(bfr)-1,
                    "Unable to remove project: %s",
                    strerror(errno));
            buffer_copy_string(b, bfr);
            con->http_status = 500;
            return HANDLER_FINISHED;
        }
    }
    else if (op == FILE_LIST) {
        struct dirent *de;
        DIR *proj_dir;
        char proj[2048];

        snprintf(proj, sizeof(proj)-1, "%s/%s", PROJECT_DIR, project_name);

        proj_dir = opendir(proj);
        if (!proj_dir) {
            con->http_status = 500;
            return HANDLER_FINISHED;
        }

        while ((de = readdir(proj_dir)) != NULL) {
            char entry[2048];

            /* Only accept files */
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;

            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(entry, sizeof(entry)-1, "%s\n", de->d_name);
            buffer_copy_string(b, entry);
        }
        closedir(proj_dir);
    }
    else if (op == FILE_CREATE) {
        char full_path[2048];
        char bfr[1024];
        int fd;
        bzero(full_path, sizeof(full_path));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);

        fd = open(full_path, O_WRONLY | O_CREAT, 0644);
        if (-1 == fd) {
            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(bfr, sizeof(bfr)-1,
                     "Unable to create file: %s",
                     strerror(errno));
            buffer_copy_string(b, bfr);
            con->http_status = 500;
            return HANDLER_FINISHED;
        }

        /* Stolen from mod_cgi.c */
		if (con->request.content_length) {
			chunkqueue *cq = con->request_content_queue;
			chunk *c;

			/* there is content to send */
			for (c = cq->first; c; c = cq->first) {
				int r = 0;

				/* copy all chunks */
				switch(c->type) {
				case FILE_CHUNK:

					if (c->file.mmap.start == MAP_FAILED) {
						if (-1 == c->file.fd &&  /* open the file if not already open */
						    -1 == (c->file.fd = open(c->file.name->ptr, O_RDONLY))) {
							log_error_write(srv, __FILE__, __LINE__, "ss", "open failed: ", strerror(errno));

							close(fd);
							return -1;
						}

						c->file.mmap.length = c->file.length;

						if (MAP_FAILED == (c->file.mmap.start = mmap(0,  c->file.mmap.length, PROT_READ, MAP_SHARED, c->file.fd, 0))) {
							log_error_write(srv, __FILE__, __LINE__, "ssbd", "mmap failed: ",
									strerror(errno), c->file.name,  c->file.fd);

							close(fd);
							return -1;
						}

						close(c->file.fd);
						c->file.fd = -1;

						/* chunk_reset() or chunk_free() will cleanup for us */
					}

					if ((r = write(fd, c->file.mmap.start + c->offset, c->file.length - c->offset)) < 0) {
						switch(errno) {
						case ENOSPC:
							con->http_status = 507;
							break;
						case EINTR:
							continue;
						default:
							con->http_status = 403;
							break;
						}
					}
					break;
				case MEM_CHUNK:
					if ((r = write(fd, c->mem->ptr + c->offset, c->mem->used - c->offset - 1)) < 0) {
						switch(errno) {
						case ENOSPC:
							con->http_status = 507;
							break;
						case EINTR:
							continue;
						default:
							con->http_status = 403;
							break;
						}
					}
					break;
				case UNUSED_CHUNK:
					break;
				}

				if (r > 0) {
					c->offset += r;
					cq->bytes_out += r;
				} else {
					log_error_write(srv, __FILE__, __LINE__, "ss", "write() failed due to: ", strerror(errno)); 
					con->http_status = 500;
					break;
				}
				chunkqueue_remove_finished_chunks(cq);
			}
		}

		close(fd);
    }
    else if (op == FILE_RENAME) {
        char full_path[2048];
        char full_path2[2048];
        char bfr[1024];
        int fd;
        bzero(full_path, sizeof(full_path));
        bzero(full_path2, sizeof(full_path2));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);
        snprintf(full_path2, sizeof(full_path2)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file2_name);

        if (rename(full_path, full_path2) < 0) {
            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(bfr, sizeof(bfr)-1,
                    "Unable to rename file: %s", strerror(errno));
            buffer_copy_string(b, bfr);
            con->http_status = 500;
            return HANDLER_FINISHED;
        }
    }
    else if (op == FILE_LINK) {
        char full_path[2048];
        char project2_name[2048];
        char bfr[1024];
        int fd;
        bzero(full_path, sizeof(full_path));
        bzero(project2_name, sizeof(project2_name));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);
        snprintf(project2_name, sizeof(project2_name)-1,
                 "%s/%s/%s", PROJECT_DIR, file2_name, file_name);

        if (link(full_path, project2_name) < 0) {
            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(bfr, sizeof(bfr)-1,
                    "Unable to link file: %s", strerror(errno));
            buffer_copy_string(b, bfr);
            con->http_status = 500;
            return HANDLER_FINISHED;
        }
    }
    else if (op == FILE_FETCH) {
        char full_path[2048];
        char bfr[1024];
        struct stat st;

        bzero(full_path, sizeof(full_path));
        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);
        if (lstat(full_path, &st) < 0 || !(st.st_mode | S_IFREG)) {
            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(bfr, sizeof(bfr)-1,
                    "Unable to read file: %s", strerror(errno));
            buffer_copy_string(b, bfr);
            con->http_status = 500;
            return HANDLER_FINISHED;
        }
        b = buffer_init();
        buffer_copy_string(b, full_path);
        chunkqueue_append_file(con->write_queue, b, 0, st.st_size);
        buffer_free(b);
    }
    else if (op == FILE_DELETE) {
        char full_path[2048];
        char bfr[1024];
        int fd;
        bzero(full_path, sizeof(full_path));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);

        if (unlink(full_path) < 0) {
            b = chunkqueue_get_append_buffer(con->write_queue);
            snprintf(bfr, sizeof(bfr)-1,
                    "Unable to remove file: %s", strerror(errno));
            buffer_copy_string(b, bfr);
            con->http_status = 500;
            return HANDLER_FINISHED;
        }
    }

    /* An empty request simply lists all projects */
    con->file_started  = 1;
    con->file_finished = 1;


    return HANDLER_FINISHED;
}


URIHANDLER_FUNC(mod_netv_uri_handler) {
	plugin_data *p = p_d;
    UNUSED(p);

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	if (con->uri.path->used == 0) return HANDLER_GO_ON;

    if (!strncmp(con->uri.path->ptr, "/file/", strlen("/file/")))
        return handle_file_uri(srv, con, con->uri.path->ptr+strlen("/file/"));
     if (!strncmp(con->uri.path->ptr, "/lua/", strlen("/lua/")))
         return handle_lua_uri(srv, con, con->uri.path->ptr+strlen("/lua/"));
    return HANDLER_GO_ON;

}

/* this function is called at dlopen() time and inits the callbacks */

int mod_netv_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("netv");

	p->init        = mod_netv_init;
	p->handle_uri_clean  = mod_netv_uri_handler;
	p->set_defaults  = mod_netv_set_defaults;
	p->cleanup     = mod_netv_free;

	p->data        = NULL;

	return 0;
}

