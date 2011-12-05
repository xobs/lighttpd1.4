#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#define PROJECT_DIR "/Users/smc/Sites/dev/luaed/projects"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define LUA_MAXINPUT 512
#define DEFAULT_STDIO_TIMEOUT 30
#define MAX_STDIO_TIMEOUT 120


/* plugin config for all request/connections */

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

enum lua_operation {
    LUA_EVAL,
    LUA_OPEN,
    LUA_RUN,
    LUA_STDIO,
    LUA_STATE,
    LUA_PING,
    LUA_BPADD,
    LUA_BPGET,
    LUA_BPDEL,
    LUA_CLOSE,
    LUA_LIST,
    LUA_UNKNOWN,
};

enum lua_cmd {
    LC_RUN,         // LUA should run some code
    LC_EVAL,        // LUA should eval the code and return the result
    LC_PAUSE,       // LUA should pause.  A breakpoint may be specified.
    LC_CONTINUE,    // LUA should continue where it left off.
    LC_ERROR,       // Indicates an error occurred
    LC_UNKNOWN,
};

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

struct netv_lua_state {
    pid_t        pid;
    int          in_fd;
    int          out_fd;
    int          in_ctrl;
    int          out_ctrl;
    int          last_ping;
    char         project[1024];
    char         filename[1024];
    lua_State   *L;
};

#define MAX_THREAD_ID 32
static struct netv_lua_state nlua_states[MAX_THREAD_ID];
static char nlua_pool_status[MAX_THREAD_ID]; // TODO: Turn this into a bitmap


static const char *
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

static const char *
lop_to_str(enum lua_operation op)
{
    if (op == LUA_EVAL)
        return "LUA_EVAL";
    if (op == LUA_OPEN)
        return "LUA_OPEN";
    if (op == LUA_RUN)
        return "LUA_RUN";
    if (op == LUA_STDIO)
        return "LUA_STDIO";
    if (op == LUA_STATE)
        return "LUA_STATE";
    if (op == LUA_PING)
        return "LUA_PING";
    if (op == LUA_BPADD)
        return "LUA_BPADD";
    if (op == LUA_BPGET)
        return "LUA_BPGET";
    if (op == LUA_BPDEL)
        return "LUA_BPDEL";
    if (op == LUA_CLOSE)
        return "LUA_CLOSE";
    if (op == LUA_LIST)
        return "LUA_LIST";
    if (op == LUA_UNKNOWN)
        return "LUA_UNKNOWN";
    return "Please update lop_to_str()";
}

static const char *
lc_to_str(enum lua_cmd ls) {
    if (ls == LC_RUN)
        return "LC_RUN";
    if (ls == LC_EVAL)
        return "LC_EVAL";
    if (ls == LC_PAUSE)
        return "LC_PAUSE";
    if (ls == LC_CONTINUE)
        return "LC_CONTINUE";
    if (ls == LC_ERROR)
        return "LC_ERROR";
    if (ls == LC_UNKNOWN)
        return "LC_UNKNOWN";
    return "Please update lc_to_str()";
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
make_error(connection *con, char *msg, int err)
{
    char bfr[2048];
    buffer *b;

    b = chunkqueue_get_append_buffer(con->write_queue);
    snprintf(bfr, sizeof(bfr)-1, "%s: %s\n", msg, strerror(err));
    buffer_copy_string(b, bfr);
    con->http_status = 500;
    return HANDLER_FINISHED;
}



/* ------- LUA INTERPRETER FUNCTIONS (mostly run in their own fork) -------- */

static lua_State *globalL = NULL;
static const char *progname = "luaed";

static void lstop(lua_State *L, lua_Debug *ar)
{
    (void)ar;  /* unused arg. */
    lua_sethook(L, NULL, 0, 0);
    /* Avoid luaL_error -- a C hook doesn't add an extra frame. */
    luaL_where(L, 0);
    lua_pushfstring(L, "%sinterrupted!", lua_tostring(L, -1));
    lua_error(L);
}

static void laction(int i)
{
    signal(i, SIG_DFL); /* if another SIGINT happens before lstop,
                           terminate process (default action) */
    lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}

static void l_message(const char *pname, const char *msg)
{
    if (pname) fprintf(stderr, "%s: ", pname);
    fprintf(stderr, "%s\n", msg);
    fflush(stderr);
}

static int report(lua_State *L, int status)
{
    if (status && !lua_isnil(L, -1)) {
        const char *msg = lua_tostring(L, -1);
        if (msg == NULL)
            msg = "(error object is not a string)";
        l_message(progname, msg);
        lua_pop(L, 1);
    }
    fflush(stdout);
    fflush(stderr);
    return status;
}

static int traceback(lua_State *L)
{
    if (!lua_isstring(L, 1))  /* 'message' not a string? */
        return 1;  /* keep it intact */
    lua_getfield(L, LUA_GLOBALSINDEX, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }
    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }
    lua_pushvalue(L, 1);  /* pass error message */
    lua_pushinteger(L, 2);  /* skip this function and traceback */
    lua_call(L, 2, 1);  /* call debug.traceback */
    return 1;
}

static int incomplete(lua_State *L, int status)
{
    if (status == LUA_ERRSYNTAX) {
        size_t lmsg;
        const char *msg = lua_tolstring(L, -1, &lmsg);
        const char *tp = msg + lmsg - (sizeof(LUA_QL("<eof>")) - 1);
        if (strstr(msg, LUA_QL("<eof>")) == tp) {
            lua_pop(L, 1);
            return 1;
        }
    }
    return 0;  /* else... */
}

static int docall(lua_State *L, int narg, int clear)
{
    int status;
    int base = lua_gettop(L) - narg;  /* function index */
    lua_pushcfunction(L, traceback);  /* push traceback function */
    lua_insert(L, base);  /* put it under chunk and args */
    signal(SIGINT, laction);
    status = lua_pcall(L, narg, (clear ? 0 : LUA_MULTRET), base);
    signal(SIGINT, SIG_DFL);
    lua_remove(L, base);  /* remove traceback function */
    /* force a complete garbage collection in case of errors */
    if (status != 0)
        lua_gc(L, LUA_GCCOLLECT, 0);
    return status;
}



static int pushline(lua_State *L, int firstline)
{
    char buf[LUA_MAXINPUT];
    //write_prompt(L, firstline);
    if (fgets(buf, LUA_MAXINPUT, stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n')
            buf[len-1] = '\0';
        if (firstline && buf[0] == '=')
            lua_pushfstring(L, "return %s", buf+1);
        else
            lua_pushstring(L, buf);
        return 1;
    }
    return 0;
}

static int loadline(lua_State *L)
{
    int status;
    lua_settop(L, 0);
    if (!pushline(L, 1))
        return -1;  /* no input */
    for (;;) {  /* repeat until gets a complete line */
        status = luaL_loadbuffer(L, lua_tostring(L, 1), lua_strlen(L, 1), "=stdin");
        if (!incomplete(L, status))
         break;  /* cannot try to add lines? */
        if (!pushline(L, 0))  /* no more input? */
            return -1;
        lua_pushliteral(L, "\n");  /* add a new line... */
        lua_insert(L, -2);  /* ...between the two lines */
        lua_concat(L, 3);  /* join them */
    }
    lua_remove(L, 1);  /* remove line */
    return status;
}



static void
nlua_thread(int pin, int pout, char *project, char *filename)
{
    char cmd[4096];
    int cmd_size;

    lua_State *L;
    L = lua_open();

    if (!L) {
        cmd[0] = LC_ERROR;
        cmd_size = snprintf(cmd+1, sizeof(cmd)-2, "Unable to open lua") + 1;
        write(1, cmd, cmd_size);
        exit(0);
    }

    luaL_openlibs(L);

    /* If a filename was specified, load it in and run it */
    if (project && *project) {
        char full_filename[2048];
        if (filename && *filename)
            snprintf(full_filename, sizeof(full_filename)-1,
                    "%s/%s/%s", PROJECT_DIR, project, filename);
        else
            snprintf(full_filename, sizeof(full_filename)-1,
                    "%s/%s", PROJECT_DIR, project);

        if (luaL_dofile(L, full_filename)) {
            cmd[0] = LC_ERROR;
            cmd_size = snprintf(cmd+1, sizeof(cmd)-2, "Unable to load file: %s",
                    lua_tostring(L, 1)) + 1;
            write(1, cmd, cmd_size);
        }
    }

    /* If no file was specified, enter REPL mode */
    else {
        int status;
        while ((status = loadline(L)) != -1) {
            if (status == 0)
                status = docall(L, 0, 0);
            report(L, status);
            if (status == 0 && lua_gettop(L) > 0) {  /* any result to print? */
                lua_getglobal(L, "print");
                lua_insert(L, 1);
                if (lua_pcall(L, lua_gettop(L)-1, 0, 0) != 0)
                    l_message(progname,
                        lua_pushfstring(L, "error calling " LUA_QL("print") " (%s)",
                        lua_tostring(L, -1)));
            }
        }
        lua_settop(L, 0);
        fputs("\n", stdout);
        fflush(stdout);
    }

    lua_close(L);
    close(pin);
    close(pout);
    exit(0);

    return;
}


static int
nlua_stdio(server *srv, connection *con, int id, int timeout)
{
    buffer *b;

    /* If it's a POST, then write to Lua's stdin */
    if (con->request.http_method == HTTP_METHOD_POST) {
        char *temp_in;
        int in_ptr = 0;
        int offset;
        chunkqueue *cq = con->request_content_queue;
        chunk *c;

        /* If there's no input, there's nothing to do */
        if (!con->request.content_length)
            return HANDLER_FINISHED;

        temp_in = malloc(con->request.content_length);
        if (!temp_in)
            return make_error(con, "Stdin size to large", ENOMEM);

        /* there is content to eval */
        for (c = cq->first; c; c = cq->first) {
            int r = 0;

            /* copy all chunks */
            switch(c->type) {
            case FILE_CHUNK:

                if (c->file.mmap.start == MAP_FAILED) {
                    if (-1 == c->file.fd &&  /* open the file if not already open */
                        -1 == (c->file.fd = open(c->file.name->ptr, O_RDONLY))) {
                        //log_error_write(srv, __FILE__, __LINE__, "ss", "open failed: ", strerror(errno));

                        free(temp_in);
                        return -1;
                    }

                    c->file.mmap.length = c->file.length;

                    if (MAP_FAILED == (c->file.mmap.start = mmap(0,  c->file.mmap.length, PROT_READ, MAP_SHARED, c->file.fd, 0))) {
                        log_error_write(srv, __FILE__, __LINE__, "ssbd", "mmap failed: ", strerror(errno), c->file.name,  c->file.fd);

                        free(temp_in);
                        return -1;
                    }

                    close(c->file.fd);
                    c->file.fd = -1;

                    /* chunk_reset() or chunk_free() will cleanup for us */
                }

                memcpy(temp_in+in_ptr, c->file.mmap.start+c->offset,
                        c->file.length - c->offset);
                r = c->file.length - c->offset;
                break;
            case MEM_CHUNK:
                memcpy(temp_in+in_ptr,
                        c->mem->ptr + c->offset,
                        c->mem->used - c->offset - 1);
                r = c->mem->used - c->offset - 1;
                break;
            case UNUSED_CHUNK:
                break;
            }

            c->offset += r;
            cq->bytes_out += r;
            in_ptr += r;
            chunkqueue_remove_finished_chunks(cq);
        }

        
        /* Write the buffered value to the Lua interpreter */
        offset = 0;
        while (offset < in_ptr) {
            int i;
            i = write(nlua_states[id].in_fd, temp_in+offset, in_ptr-offset);
            if (i < 0) {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                break;

                kill(nlua_states[id].pid, SIGKILL);
                kill(nlua_states[id].pid, SIGTERM);
                close(nlua_states[id].in_fd);
                nlua_states[id].in_fd = -1;
                nlua_pool_status[id] = 0;
                return make_error(con, "Unable to write to stdin", errno);
            }
            offset += i;
        }
    }

    /* If it's not a POST, then read from stdout / stderr */
    else if (con->request.http_method == HTTP_METHOD_GET) {
        fd_set s;
        struct timeval t = {timeout, 0};
        int i;
        b = chunkqueue_get_append_buffer(con->write_queue);

        FD_ZERO(&s);
        FD_SET(nlua_states[id].out_fd, &s);

        i = select(nlua_states[id].out_fd+1, &s, NULL, NULL, &t);
        log_error_write(srv, __FILE__, __LINE__, 
                "sdsd", "select() returned", i,
                "for fd", nlua_states[id].out_fd);
        if (i > 0) {
            char bfr[4096];
            i = read(nlua_states[id].out_fd, bfr, sizeof(bfr));
            if (i == -1 && (errno == EINTR || errno == EAGAIN)) {
                /* Interrupted, but try again */
                buffer_copy_string_len(b, "\0", 1);
                return HANDLER_FINISHED;
            }

            else if (i == -1) {
                /* Unrecoverable error */
                kill(nlua_states[id].pid, SIGKILL);
                kill(nlua_states[id].pid, SIGTERM);
                close(nlua_states[id].out_fd);
                nlua_states[id].out_fd = -1;
                nlua_pool_status[id] = 0;
                return make_error(con, "Unable to write to stdin", errno);
            }

            else if (i == 0) {
                /* Connection closed */
                close(nlua_states[id].out_fd);
                nlua_states[id].out_fd = -1;
                nlua_pool_status[id] = 0;
                con->http_status = 204;
            }
            else {
                buffer_copy_string_len(b, bfr, i);
            }
        }

        else if (!i || (i == -1 && (errno == EINTR || errno == EAGAIN))) {
            /* No data to read */
            buffer_copy_string_len(b, "\0", 1);
        }
        else {
            /* Error occurred */
            kill(nlua_states[id].pid, SIGKILL);
            kill(nlua_states[id].pid, SIGTERM);
            close(nlua_states[id].out_fd);
            nlua_states[id].out_fd = -1;
            nlua_pool_status[id] = 0;
            buffer_copy_string_len(b, "\0", 1);
            return make_error(con, "Unable to read from stdout", errno);
        }
    }
    else {
        return make_error(con, "Unrecognized http method", 0);
    }
    return HANDLER_FINISHED;
}

static void
nlua_sig(int sig)
{
    UNUSED(sig);
    fflush(stdout);
    exit(0);
}


/* Open a LUA state.  Forks a new process and sets it to be idle */
static int
nlua_open(server *srv, connection *con, char *project, char *filename)
{
    int thread_id = -1;
    int i;
    int p[4][2];
    UNUSED(srv);
    UNUSED(con);

    signal(SIGTERM, nlua_sig);

    for(i=0; i<MAX_THREAD_ID && thread_id < 0; i++) 
        if (!nlua_pool_status[i])
            thread_id = i;
    if (thread_id < 0)
        return -ENOSPC;


    nlua_pool_status[thread_id] = 1;


    if (-1 == pipe(p[0])) {
        nlua_pool_status[thread_id] = 0;
        return -errno;
    }

    if (-1 == pipe(p[1])) {
        close(p[0][0]);
        close(p[0][1]);
        nlua_pool_status[thread_id] = 0;
        return -errno;
    }
    pipe(p[2]);
    pipe(p[3]);

    nlua_states[thread_id].pid = fork();

    if (-1 == nlua_states[thread_id].pid) {
        close(p[0][0]);
        close(p[0][1]);
        close(p[1][0]);
        close(p[1][1]);
        close(p[2][0]);
        close(p[2][1]);
        close(p[3][0]);
        close(p[3][1]);
        nlua_pool_status[thread_id] = 0;
        return -errno;
    }

    else if(!nlua_states[thread_id].pid) {
        /* Make p[1][1] be stdin */
        if (p[1][1] != 1) {
            dup2(p[1][1], fileno(stdout));
            dup2(p[1][1], fileno(stderr));
            close(p[1][1]);
        }

        /* Make p[0][0] be stdin */
        if (p[0][0] != 0) {
            dup2(p[0][0], fileno(stdin));
            close(p[0][0]);
        }

        close(p[0][1]);
        close(p[1][0]);
        close(p[2][1]);
        close(p[3][0]);

        /* Reset buffering on the new descriptors */
        setlinebuf(stdin);
        setlinebuf(stdout);
        setlinebuf(stderr);

        nlua_thread(p[2][0], p[3][1], project, filename);
        exit(0);
    }

    close(p[0][0]);
    close(p[1][1]);
    close(p[2][0]);
    close(p[3][1]);

    /* We're running as parent process */
    nlua_states[thread_id].in_fd    = p[0][1];
    nlua_states[thread_id].out_fd   = p[1][0];
    nlua_states[thread_id].in_ctrl  = p[2][1];
    nlua_states[thread_id].out_ctrl = p[3][0];

    return thread_id;
}


static int
nlua_close(server *srv, connection *con, int thread_id)
{
    UNUSED(srv);
    UNUSED(con);

    if (!nlua_pool_status[thread_id])
        return 0;

    kill(nlua_states[thread_id].pid, SIGTERM);
    kill(nlua_states[thread_id].pid, SIGKILL);
    nlua_pool_status[thread_id] = 0;
    return 0;
}


static int
nlua_eval(server *srv, connection *con)
{
    chunkqueue *cq = con->request_content_queue;
    chunk *c;
    buffer *b;
    char *program;
    int prog_ptr = 0;
    lua_State *lua;
    int streamer[2];
    int in, out;
    UNUSED(srv);

    close(0);

    /* If there's no program, there's nothing to do */
    if (!con->request.content_length)
        return HANDLER_FINISHED;

    program = malloc(con->request.content_length+1);
    if (!program)
        return make_error(con, "Program size to large", ENOMEM);
    program[con->request.content_length] = '\0';

    /* there is content to eval */
    for (c = cq->first; c; c = cq->first) {
        int r = 0;

        /* copy all chunks */
        switch(c->type) {
        case FILE_CHUNK:

            if (c->file.mmap.start == MAP_FAILED) {
                if (-1 == c->file.fd &&  /* open the file if not already open */
                    -1 == (c->file.fd = open(c->file.name->ptr, O_RDONLY))) {
                    //log_error_write(srv, __FILE__, __LINE__, "ss", "open failed: ", strerror(errno));

                    free(program);
                    return -1;
                }

                c->file.mmap.length = c->file.length;

                if (MAP_FAILED == (c->file.mmap.start = mmap(0,  c->file.mmap.length, PROT_READ, MAP_SHARED, c->file.fd, 0))) {
                    //log_error_write(srv, __FILE__, __LINE__, "ssbd", "mmap failed: ", strerror(errno), c->file.name,  c->file.fd);

                    free(program);
                    return -1;
                }

                close(c->file.fd);
                c->file.fd = -1;

                /* chunk_reset() or chunk_free() will cleanup for us */
            }

            memcpy(program+prog_ptr, c->file.mmap.start+c->offset,
                    c->file.length - c->offset);
            r = c->file.length - c->offset;
            break;
        case MEM_CHUNK:
            memcpy(program+prog_ptr,
                    c->mem->ptr + c->offset,
                    c->mem->used - c->offset - 1);
            r = c->mem->used - c->offset - 1;
            break;
        case UNUSED_CHUNK:
            break;
        }

        c->offset += r;
        cq->bytes_out += r;
        prog_ptr += r;
        chunkqueue_remove_finished_chunks(cq);
    }

    lua = lua_open();
    if (!lua)
        return make_error(con, "Unable to open lua", errno);

    luaL_openlibs(lua);

    pipe(streamer);
    out = dup2(streamer[1], 0);
    in = streamer[0];

    if (streamer[1] != out)
        close(streamer[1]);

    if (luaL_dostring(lua, program)) {
        char errmsg[2048];
        snprintf(errmsg, sizeof(errmsg)-1,
                "LUA program \"%s\" encountered an error: %s", program, lua_tostring(lua, 1));
        make_error(con, errmsg, 1);
        con->http_status = 200;
    }
    else {
        char data[4096];
        int len;
        bzero(data, sizeof(data));
        len = read(in, data, sizeof(data));
        b = chunkqueue_get_append_buffer(con->write_queue);
        buffer_copy_string_len(b, data, len);
        con->http_status = 200;
    }
    lua_close(lua);
    free(program);

    close(streamer[1]);
    close(streamer[0]);
    close(out);
    close(in);

    return HANDLER_FINISHED;
}






static server *g_srv;
static void my_reaper(int sig) {
    pid_t pid;
    UNUSED(sig);
    
    pid = waitpid(-1, NULL, WNOHANG);
    if (pid > 0) {
        int i;
        for (i=0; i<MAX_THREAD_ID; i++) {
            if (nlua_states[i].pid == pid) {
                /* -- let the file handles drain on their own
                close(nlua_states[i].in_fd);
                close(nlua_states[i].out_fd);
                close(nlua_states[i].in_ctrl);
                close(nlua_states[i].out_ctrl);
                */
                nlua_pool_status[i] = 0;
            }
        }
        if (g_srv)
            log_error_write(g_srv, __FILE__, __LINE__, "sd",
                    "Got SIGCHLD for PID", pid);
    }

}


/* init the plugin data */
INIT_FUNC(mod_netv_init) {
	plugin_data *p;
    int i;

	p = calloc(1, sizeof(*p));

	p->match_buf = buffer_init();
    for (i=0; i<MAX_THREAD_ID; i++) {
        nlua_states[i].in_fd    = -1;
        nlua_states[i].out_fd   = -1;
        nlua_states[i].in_ctrl  = -1;
        nlua_states[i].out_ctrl = -1;
    }

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
parse_lua_uri(char *uri, char *cmd, char *token, char *arg, int sz)
{
    char *uri_tmp;
    char *slashes;
    int len;

    bzero(cmd, sz);
    bzero(token, sz);
    bzero(arg, sz);

    slashes = strchr(uri, '/');
    uri_tmp = uri;

    len = sz-1;
    if (slashes && slashes-uri_tmp < len)
        len = slashes-uri_tmp;
    strncpy(cmd, uri_tmp, len);

    if (slashes) {
        uri_tmp = slashes+1;
        slashes = strchr(uri_tmp, '/');

        if (slashes) {
            len = sz-1;
            if (slashes-uri_tmp < len)
                len = slashes-uri_tmp;
            strncpy(token, uri_tmp, len);

            uri_tmp = slashes+1;
            slashes = strchr(uri_tmp, '/');

            if (slashes) {
                len = sz-1;
                if (slashes-uri_tmp < len)
                    len = slashes-uri_tmp;
                strncpy(arg, uri_tmp, len);
            }
            else if(*uri_tmp)
                strncpy(arg, uri_tmp, sz);
        }
        else if(*uri_tmp)
            strncpy(token, uri_tmp, sz);
    }

    strrep(cmd, '/', '\0');
    strrep(token, '/', '\0');
    strrep(arg, '/', '\0');

    return 0;
}

static enum lua_operation
determine_lua_operation(char *cmd, char *token, char *arg)
{
    enum lua_operation lo;
    UNUSED(token);
    UNUSED(arg);

    if (!strcmp(cmd, "list")) {
        lo = LUA_LIST;
    }

    else if(!strcmp(cmd, "eval")) {
        lo = LUA_EVAL;
    }

    else if(!strcmp(cmd, "close")) {
        lo = LUA_CLOSE;
    }

    else if(!strcmp(cmd, "bpdel")) {
        lo = LUA_BPDEL;
    }

    else if(!strcmp(cmd, "bpget")) {
        lo = LUA_BPGET;
    }

    else if(!strcmp(cmd, "bpadd")) {
        lo = LUA_BPADD;
    }

    else if(!strcmp(cmd, "ping")) {
        lo = LUA_PING;
    }

    else if(!strcmp(cmd, "state")) {
        lo = LUA_STATE;
    }

    else if(!strcmp(cmd, "stdio")) {
        lo = LUA_STDIO;
    }

    else if(!strcmp(cmd, "run")) {
        lo = LUA_RUN;
    }

    else if(!strcmp(cmd, "open")) {
        lo = LUA_OPEN;
    }
    else {
        lo = LUA_UNKNOWN;
    }
    return lo;
}


static int
handle_lua_uri(server *srv, connection *con, char *uri)
{
    char cmd[1024];
    char token[1024];
    char arg[1024];
    enum lua_operation lo;
    buffer *b;
    int id; // token ID, parsed as an int

    parse_lua_uri(uri, cmd, token, arg, sizeof(cmd));
    b = chunkqueue_get_append_buffer(con->write_queue);


    con->file_started  = 1;
    con->file_finished = 1;

    /* Overwrite lighttpd's use of default error handlers */
    con->mode = EXTERNAL;


    lo = determine_lua_operation(cmd, token, arg);
    log_error_write(srv, __FILE__, __LINE__, "sssssssssds",
            "Raw URI:", uri,
            " command name:", cmd,
            " token:", token,
            " arg:", arg,
            " lua operation:", lo, lop_to_str(lo));


    if (lo == LUA_EVAL)
        return nlua_eval(srv, con);

    else if(lo == LUA_OPEN) {
        char data[4096];

        id = nlua_open(srv, con, token, arg);
        if (id < 0)
            return make_error(con, "Unable to open LUA environment", -id);

        snprintf(data, sizeof(data)-1, "%d\n", id);
        buffer_copy_string(b, data);
    }

    else if (lo == LUA_CLOSE) {
        id = strtoul(token, NULL, 16);
        if (id > MAX_THREAD_ID)
            return make_error(con, "Invalid thread ID specified", EINVAL);
        nlua_close(srv, con, id);
        buffer_copy_string(b, "OK\n");
    }

    else if (lo == LUA_STDIO) {
        int timeout = DEFAULT_STDIO_TIMEOUT;
        id = strtoul(token, NULL, 0);
        if (id > MAX_THREAD_ID)
            return make_error(con, "Invalid thread ID specified", EINVAL);

        if (*arg) {
            timeout = strtoul(arg, NULL, 0);
            if (timeout < 0 || timeout > MAX_STDIO_TIMEOUT)
                timeout = DEFAULT_STDIO_TIMEOUT;
        }

        return nlua_stdio(srv, con, id, timeout);
    }

    else if (lo == LUA_LIST) {
        for (id=0; id<MAX_THREAD_ID; id++) {
            if (nlua_pool_status[id]) {
                buffer_append_long(b, id);
                buffer_append_string(b, "\n");
            }
        }
    }


    else if (lo == LUA_UNKNOWN)
        return make_error(con, "No valid LUA command specified", EINVAL);

    return HANDLER_FINISHED;
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

    /* Overwrite lighttpd's use of default error handlers */
    con->mode = EXTERNAL;

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
     || strstr(file2_name, ".."))
        return make_error(con, "Invalid project name", EISDIR);

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
        if (-1 == res)
            return make_error(con, "Unable to create project", errno);

        b = chunkqueue_get_append_buffer(con->write_queue);
        buffer_copy_string(b, "OK\n");
    }

    else if (op == PROJ_LIST) {
        DIR *proj_dir;
        struct dirent *de;

        proj_dir = opendir(PROJECT_DIR);
        if (!proj_dir)
            return make_error(con, "Unable to open project dir", errno);

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

        snprintf(proj, sizeof(proj)-1, "%s/%s", PROJECT_DIR, project_name);

        proj_dir = opendir(proj);
        if (!proj_dir)
            return make_error(con, "Unable to open project dir", errno);

        while ((de = readdir(proj_dir)) != NULL) {
            char entry[2048];

            /* Only accept files */
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            snprintf(entry, sizeof(entry)-1, "%s/%s/%s", PROJECT_DIR,
                    project_name, de->d_name);
            if (unlink(entry))
                return make_error(con,
                                  "Unable to remove file from project",
                                  errno);
        }
        closedir(proj_dir);

        if (rmdir(proj) < 0)
            return make_error(con, "Unable to remove project", errno);
        b = chunkqueue_get_append_buffer(con->write_queue);
        buffer_copy_string(b, "OK\n");
    }
    else if (op == FILE_LIST) {
        struct dirent *de;
        DIR *proj_dir;
        char proj[2048];

        snprintf(proj, sizeof(proj)-1, "%s/%s", PROJECT_DIR, project_name);

        proj_dir = opendir(proj);
        if (!proj_dir)
            return make_error(con, "Unable to get file listing", errno);

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
        int fd;
        bzero(full_path, sizeof(full_path));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);

        fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (-1 == fd)
            return make_error(con, "Unable to create file", errno);

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
                    close(fd);
                    return make_error(con, "Unable to write file", errno);
					break;
				}
				chunkqueue_remove_finished_chunks(cq);
			}
		}

		close(fd);
        b = chunkqueue_get_append_buffer(con->write_queue);
        buffer_copy_string(b, "OK\n");
    }
    else if (op == FILE_RENAME) {
        char full_path[2048];
        char full_path2[2048];
        bzero(full_path, sizeof(full_path));
        bzero(full_path2, sizeof(full_path2));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);
        snprintf(full_path2, sizeof(full_path2)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file2_name);

        if (rename(full_path, full_path2) < 0)
            return make_error(con, "Unable to rename file", errno);
        b = chunkqueue_get_append_buffer(con->write_queue);
        buffer_copy_string(b, "OK\n");
    }
    else if (op == FILE_LINK) {
        char full_path[2048];
        char project2_name[2048];
        bzero(full_path, sizeof(full_path));
        bzero(project2_name, sizeof(project2_name));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);
        snprintf(project2_name, sizeof(project2_name)-1,
                 "%s/%s/%s", PROJECT_DIR, file2_name, file_name);

        if (link(full_path, project2_name) < 0)
            return make_error(con, "Unable to link file", errno);
        b = chunkqueue_get_append_buffer(con->write_queue);
        buffer_copy_string(b, "OK\n");
    }
    else if (op == FILE_FETCH) {
        char full_path[2048];
        struct stat st;

        bzero(full_path, sizeof(full_path));
        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);
        if (lstat(full_path, &st) < 0 || !(st.st_mode | S_IFREG))
            return make_error(con, "Unable to read file", errno);
        b = buffer_init();
        buffer_copy_string(b, full_path);
        chunkqueue_append_file(con->write_queue, b, 0, st.st_size);
        buffer_free(b);
    }
    else if (op == FILE_DELETE) {
        char full_path[2048];
        bzero(full_path, sizeof(full_path));

        snprintf(full_path, sizeof(full_path)-1,
                 "%s/%s/%s", PROJECT_DIR, project_name, file_name);

        if (unlink(full_path) < 0)
            return make_error(con, "Unable to remove file", errno);
        b = chunkqueue_get_append_buffer(con->write_queue);
        buffer_copy_string(b, "OK\n");
    }


    con->http_status = 200;
    return HANDLER_FINISHED;
}


URIHANDLER_FUNC(mod_netv_uri_handler) {
	plugin_data *p = p_d;
    UNUSED(p);

    g_srv = srv;
    signal(SIGCHLD, my_reaper);

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

