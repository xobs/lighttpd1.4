#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "inet_ntop_cache.h"
#include "mod_proxy_core.h"
#include "mod_proxy_core_protocol.h"
#include "buffer.h"
#include "log.h"
#include "fastcgi.h"
#include "array.h"

#define CORE_PLUGIN "mod_proxy_core"

typedef struct {
	PLUGIN_DATA;

	proxy_protocol *protocol;
} protocol_plugin_data;

/**
 * we aren't supporting multiplexing
 *
 * use always the same request-id
 */
#define PROXY_FASTCGI_REQUEST_ID 1
#if 1
#define PROXY_FASTCGI_USE_KEEP_ALIVE 1
#endif

typedef struct {
	size_t   len;
	off_t    offset;
	int      type;
	int      padding;
	size_t   request_id;
} fastcgi_packet;

/**
 * The fastcgi protocol decoder will use this struct for storing state variables
 * used in decoding the stream
 */
typedef struct {
	buffer          *buf; /* holds raw header bytes or used to buffer STDERR */
	fastcgi_packet  packet; /* parsed info about current packet. */
} fcgi_state_data;

fcgi_state_data *fcgi_state_data_init(void) {
	fcgi_state_data *data;

	data = calloc(1, sizeof(*data));
	data->buf = buffer_init();

	return data;
}

void fcgi_state_data_free(fcgi_state_data *data) {
	buffer_free(data->buf);
	free(data);
}

void fcgi_state_data_reset(fcgi_state_data *data) {
	buffer_reset(data->buf);
	data->packet.len = 0;
	data->packet.offset = 0;
	data->packet.type = 0;
	data->packet.padding = 0;
	data->packet.request_id = 0;
}

SESSION_FUNC(proxy_fastcgi_init) {
	UNUSED(srv);

	if(!sess->protocol_data) {
		sess->protocol_data = fcgi_state_data_init();
	}
	return 1;
}

SESSION_FUNC(proxy_fastcgi_cleanup) {
	UNUSED(srv);

	if(sess->protocol_data) {
		fcgi_state_data_free((fcgi_state_data *)sess->protocol_data);
		sess->protocol_data = NULL;
	}
	return 1;
}

int proxy_fastcgi_get_env_fastcgi(server *srv, connection *con, plugin_data *p, proxy_session *sess) {
	char buf[32];
	const char *s;
	server_socket *srv_sock = con->srv_socket;
#ifdef HAVE_IPV6
	char b2[INET6_ADDRSTRLEN + 1];
#endif

	sock_addr our_addr;
	socklen_t our_addr_len;

	array_set_key_value(sess->env_headers, CONST_STR_LEN("SERVER_SOFTWARE"), CONST_STR_LEN(PACKAGE_NAME"/"PACKAGE_VERSION));

	if (con->server_name->used) {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("SERVER_NAME"), CONST_BUF_LEN(con->server_name));
	} else {
#ifdef HAVE_IPV6
		s = inet_ntop(srv_sock->addr.plain.sa_family,
			      srv_sock->addr.plain.sa_family == AF_INET6 ?
			      (const void *) &(srv_sock->addr.ipv6.sin6_addr) :
			      (const void *) &(srv_sock->addr.ipv4.sin_addr),
			      b2, sizeof(b2)-1);
#else
		s = inet_ntoa(srv_sock->addr.ipv4.sin_addr);
#endif
		array_set_key_value(sess->env_headers, CONST_STR_LEN("SERVER_NAME"), s, strlen(s));
	}

	array_set_key_value(sess->env_headers, CONST_STR_LEN("GATEWAY_INTERFACE"), CONST_STR_LEN("CGI/1.1"));

	ltostr(buf,
#ifdef HAVE_IPV6
	       ntohs(srv_sock->addr.plain.sa_family ? srv_sock->addr.ipv6.sin6_port : srv_sock->addr.ipv4.sin_port)
#else
	       ntohs(srv_sock->addr.ipv4.sin_port)
#endif
	       );

	array_set_key_value(sess->env_headers, CONST_STR_LEN("SERVER_PORT"), buf, strlen(buf));

	/* get the server-side of the connection to the client */
	our_addr_len = sizeof(our_addr);

	if (-1 == getsockname(con->sock->fd, &(our_addr.plain), &our_addr_len)) {
		s = inet_ntop_cache_get_ip(srv, &(srv_sock->addr));
	} else {
		s = inet_ntop_cache_get_ip(srv, &(our_addr));
	}
	array_set_key_value(sess->env_headers, CONST_STR_LEN("SERVER_ADDR"), s, strlen(s));

	ltostr(buf,
#ifdef HAVE_IPV6
	       ntohs(con->dst_addr.plain.sa_family ? con->dst_addr.ipv6.sin6_port : con->dst_addr.ipv4.sin_port)
#else
	       ntohs(con->dst_addr.ipv4.sin_port)
#endif
	       );

	array_set_key_value(sess->env_headers, CONST_STR_LEN("REMOTE_PORT"), buf, strlen(buf));

	s = inet_ntop_cache_get_ip(srv, &(con->dst_addr));
	array_set_key_value(sess->env_headers, CONST_STR_LEN("REMOTE_ADDR"), s, strlen(s));

	if (!buffer_is_empty(con->authed_user)) {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("REMOTE_USER"),
			     CONST_BUF_LEN(con->authed_user));
	}

	if (con->request.content_length > 0) {
		/* CGI-SPEC 6.1.2 and FastCGI spec 6.3 */

		/* request.content_length < SSIZE_MAX, see request.c */
		ltostr(buf, con->request.content_length);
		array_set_key_value(sess->env_headers, CONST_STR_LEN("CONTENT_LENGTH"), buf, strlen(buf));
	}


	/*
	 * SCRIPT_NAME, PATH_INFO and PATH_TRANSLATED according to
	 * http://cgi-spec.golux.com/draft-coar-cgi-v11-03-clean.html
	 * (6.1.14, 6.1.6, 6.1.7)
	 * For AUTHORIZER mode these headers should be omitted.
	 */

	array_set_key_value(sess->env_headers, CONST_STR_LEN("SCRIPT_NAME"), CONST_BUF_LEN(con->uri.path));

	if (!buffer_is_empty(con->request.pathinfo)) {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("PATH_INFO"), CONST_BUF_LEN(con->request.pathinfo));

		/* PATH_TRANSLATED is only defined if PATH_INFO is set */

		buffer_copy_string_buffer(p->tmp_buf, con->physical.doc_root);
		buffer_append_string_buffer(p->tmp_buf, con->request.pathinfo);
		array_set_key_value(sess->env_headers, CONST_STR_LEN("PATH_TRANSLATED"), CONST_BUF_LEN(p->tmp_buf));
	} else {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("PATH_INFO"), CONST_STR_LEN(""));
	}

	/*
	 * SCRIPT_FILENAME and DOCUMENT_ROOT for php. The PHP manual
	 * http://www.php.net/manual/en/reserved.variables.php
	 * treatment of PATH_TRANSLATED is different from the one of CGI specs.
	 * TODO: this code should be checked against cgi.fix_pathinfo php
	 * parameter.
	 */

	if (1) {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("SCRIPT_FILENAME"), CONST_BUF_LEN(con->physical.path));
		array_set_key_value(sess->env_headers, CONST_STR_LEN("DOCUMENT_ROOT"), CONST_BUF_LEN(con->physical.doc_root));
	}

	array_set_key_value(sess->env_headers, CONST_STR_LEN("REQUEST_URI"), CONST_BUF_LEN(con->request.orig_uri));

	if (!buffer_is_equal(sess->request_uri, con->request.orig_uri)) {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("REDIRECT_URI"), CONST_BUF_LEN(sess->request_uri));
	}
	if (!buffer_is_empty(con->uri.query)) {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("QUERY_STRING"), CONST_BUF_LEN(con->uri.query));
	} else {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("QUERY_STRING"), CONST_STR_LEN(""));
	}

	s = get_http_method_name(con->request.http_method);
	array_set_key_value(sess->env_headers, CONST_STR_LEN("REQUEST_METHOD"), s, strlen(s));
	array_set_key_value(sess->env_headers, CONST_STR_LEN("REDIRECT_STATUS"), CONST_STR_LEN("200")); /* if php is compiled with --force-redirect */
	s = get_http_version_name(con->request.http_version);
	array_set_key_value(sess->env_headers, CONST_STR_LEN("SERVER_PROTOCOL"), s, strlen(s));

#ifdef USE_OPENSSL
	if (srv_sock->is_ssl) {
		array_set_key_value(sess->env_headers, CONST_STR_LEN("HTTPS"), CONST_STR_LEN("on"));
	}
#endif

	return 0;
}

/**
 * transform the HTTP-Request headers into CGI notation
 */
int proxy_fastcgi_get_env_request(server *srv, connection *con, plugin_data *p, proxy_session *sess) {
	size_t i;

	UNUSED(srv);
	UNUSED(con);

	/* the request header got already copied into the sess->request_headers for us
	 * no extra filter is needed
	 *
	 * prepend a HTTP_ and uppercase the keys
	 */
	for (i = 0; i < sess->request_headers->used; i++) {
		data_string *ds;
		size_t j;

		ds = (data_string *)sess->request_headers->data[i];

		buffer_reset(p->tmp_buf);

		if (0 != strcasecmp(ds->key->ptr, "CONTENT-TYPE")) {
			BUFFER_COPY_STRING_CONST(p->tmp_buf, "HTTP_");
			p->tmp_buf->used--;
		}

		buffer_prepare_append(p->tmp_buf, ds->key->used + 2);
		for (j = 0; j < ds->key->used - 1; j++) {
			char c = '_';
			if (light_isalpha(ds->key->ptr[j])) {
				/* upper-case */
				c = ds->key->ptr[j] & ~32;
			} else if (light_isdigit(ds->key->ptr[j])) {
				/* copy */
				c = ds->key->ptr[j];
			}
			p->tmp_buf->ptr[p->tmp_buf->used++] = c;
		}
		p->tmp_buf->ptr[p->tmp_buf->used++] = '\0';

		array_set_key_value(sess->env_headers, CONST_BUF_LEN(p->tmp_buf), CONST_BUF_LEN(ds->value));
	}

	return 0;
}


/**
 * add a key-value pair to the fastcgi-buffer
 */

static int fcgi_env_add(buffer *env, const char *key, size_t key_len, const char *val, size_t val_len) {
	size_t len;

	if (!key || !val) return -1;

	len = key_len + val_len;

	len += key_len > 127 ? 4 : 1;
	len += val_len > 127 ? 4 : 1;

	buffer_prepare_append(env, len);

	if (key_len > 127) {
		env->ptr[env->used++] = ((key_len >> 24) & 0xff) | 0x80;
		env->ptr[env->used++] = (key_len >> 16) & 0xff;
		env->ptr[env->used++] = (key_len >> 8) & 0xff;
		env->ptr[env->used++] = (key_len >> 0) & 0xff;
	} else {
		env->ptr[env->used++] = (key_len >> 0) & 0xff;
	}

	if (val_len > 127) {
		env->ptr[env->used++] = ((val_len >> 24) & 0xff) | 0x80;
		env->ptr[env->used++] = (val_len >> 16) & 0xff;
		env->ptr[env->used++] = (val_len >> 8) & 0xff;
		env->ptr[env->used++] = (val_len >> 0) & 0xff;
	} else {
		env->ptr[env->used++] = (val_len >> 0) & 0xff;
	}

	memcpy(env->ptr + env->used, key, key_len);
	env->used += key_len;
	memcpy(env->ptr + env->used, val, val_len);
	env->used += val_len;

	return 0;
}

/**
 * init the FCGI_header
 */
static int fcgi_header(FCGI_Header * header, unsigned char type, size_t request_id, int contentLength, unsigned char paddingLength) {
	header->version = FCGI_VERSION_1;
	header->type = type;
	header->requestIdB0 = request_id & 0xff;
	header->requestIdB1 = (request_id >> 8) & 0xff;
	header->contentLengthB0 = contentLength & 0xff;
	header->contentLengthB1 = (contentLength >> 8) & 0xff;
	header->paddingLength = paddingLength;
	header->reserved = 0;

	return 0;
}


STREAM_IN_OUT_FUNC(proxy_fastcgi_get_request_chunk) {
	connection *con = sess->remote_con;
	buffer *b, *packet;
	size_t i;
	FCGI_BeginRequestRecord beginRecord;
	FCGI_Header header;
	plugin_data *p = sess->p;

	UNUSED(srv);
	UNUSED(in);

	b = chunkqueue_get_append_buffer(out);
	/* send FCGI_BEGIN_REQUEST */

	fcgi_header(&(beginRecord.header), FCGI_BEGIN_REQUEST, PROXY_FASTCGI_REQUEST_ID, sizeof(beginRecord.body), 0);
	beginRecord.body.roleB0 = FCGI_RESPONDER;
	beginRecord.body.roleB1 = 0;
#ifdef PROXY_FASTCGI_USE_KEEP_ALIVE
	beginRecord.body.flags = FCGI_KEEP_CONN;
#else
	beginRecord.body.flags = 0;
#endif
	memset(beginRecord.body.reserved, 0, sizeof(beginRecord.body.reserved));

	buffer_copy_string_len(b, (const char *)&beginRecord, sizeof(beginRecord));
	out->bytes_in += sizeof(beginRecord);

	/* send FCGI_PARAMS */
	b = chunkqueue_get_append_buffer(out);
	buffer_prepare_copy(b, 1024);

	/* fill the sess->env_headers */
	array_reset(sess->env_headers);
	proxy_fastcgi_get_env_request(srv, con, p, sess);
	proxy_fastcgi_get_env_fastcgi(srv, con, p, sess);

	packet = buffer_init();

	for (i = 0; i < sess->env_headers->used; i++) {
		data_string *ds;

		ds = (data_string *)sess->env_headers->data[i];
		fcgi_env_add(packet, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
	}

	fcgi_header(&(header), FCGI_PARAMS, PROXY_FASTCGI_REQUEST_ID, packet->used, 0);
	buffer_append_memory(b, (const char *)&header, sizeof(header));
	buffer_append_memory(b, (const char *)packet->ptr, packet->used);
	out->bytes_in += sizeof(header);
	out->bytes_in += packet->used - 1;

	buffer_free(packet);

	fcgi_header(&(header), FCGI_PARAMS, PROXY_FASTCGI_REQUEST_ID, 0, 0);
	buffer_append_memory(b, (const char *)&header, sizeof(header));
	b->used++;
	out->bytes_in += sizeof(header) + 1;

	return 0;
}

STREAM_IN_OUT_FUNC(proxy_fastcgi_stream_decoder_internal) {
	fcgi_state_data *data = (fcgi_state_data *)sess->protocol_data;
	FCGI_Header *header;
	off_t we_have = 0, we_need = 0;
	int rc = 0;
	chunk *c;

	UNUSED(srv);

	/* no data ? */
	if (!in->first) return 0;

	/* parse the packet header. */
	we_need = (FCGI_HEADER_LEN - data->packet.offset);
	if(we_need > 0) {
		/* copy fastcgi header to buffer */
		buffer_prepare_append(data->buf, we_need);
		for (c = in->first; c && we_need > 0; c = c->next) {
			if(c->mem->used == 0) continue;

			we_have = c->mem->used - c->offset - 1;
			if (we_have == 0) continue;
			if (we_have > we_need) we_have = we_need;

			buffer_append_string_len(data->buf, c->mem->ptr + c->offset, we_have);
			data->packet.offset += we_have;
			c->offset += we_have;
			in->bytes_out += we_have;
			we_need -= we_have;
		}
		/* make sure we have the full fastcgi header. */
		if(we_need > 0) {
			/* we need more data to parse the header. */
			return 0;
		}
		/* parse raw header. */
		header = (FCGI_Header *)(data->buf->ptr);

		data->packet.len = (header->contentLengthB0 | (header->contentLengthB1 << 8));
		data->packet.request_id = (header->requestIdB0 | (header->requestIdB1 << 8));
		data->packet.type = header->type;
		data->packet.padding = header->paddingLength;

		/* Finished parsing raw header bytes. */
		buffer_reset(data->buf);
	}

	/* proccess the packet's contents. */
	we_need = data->packet.len - (data->packet.offset - FCGI_HEADER_LEN);
	switch (data->packet.type) {
	case FCGI_STDOUT:
		if (we_need > 0) {
			/* copy packet contents */
			we_have = chunkqueue_steal_chunks_len(out, in->first, we_need);
			data->packet.offset += we_have;
			we_need -= we_have;
			in->bytes_out += we_have;
			out->bytes_in += we_have;
		} else {
			out->is_closed = 1;
		}
		rc = 0;
		break;
	case FCGI_STDERR:
		if(we_need > 0) {
			buffer *b = buffer_init();
			buffer_prepare_append(b, we_need);
			for (c = in->first; c && we_need > 0; c = c->next) {
				if (c->mem->used == 0) continue;

				we_have = c->mem->used - c->offset - 1;
				if (we_have == 0) continue;
				if (we_have > we_need) we_have = we_need;

				buffer_append_string_len(b, c->mem->ptr + c->offset, we_have);
				data->packet.offset += we_have;
				c->offset += we_have;
				in->bytes_out += we_have;
				we_need -= we_have;
			}
			TRACE("(fastcgi-stderr) %s", BUF_STR(b));
			buffer_free(b);
		}
		rc = 0;
		break;
	case FCGI_END_REQUEST:
		/* ignore packet content. */
		if(we_need > 0) {
			we_have = chunkqueue_skip(in, we_need);
			data->packet.offset += we_have;
			we_need -= we_have;
			in->bytes_out += we_have;
		}
		if(we_need == 0) {
#ifndef PROXY_FASTCGI_USE_KEEP_ALIVE
			sess->is_closing = 1;
#endif
			in->is_closed = 1;
			out->is_closed = 1;
			rc = 1;
		}
		break;
	default:
		TRACE("unknown packet.type: %d", data->packet.type);
		rc = -1;
		break;
	}

	/* skip packet padding, once content has been processed. */
	if(we_need == 0 && data->packet.padding > 0) {
		we_have = chunkqueue_skip(in, data->packet.padding);
		data->packet.padding -= we_have;
		in->bytes_out += we_have;
	}

	if(we_need == 0 && data->packet.padding == 0) {
		/* packet finished, reset state for next packet */
		fcgi_state_data_reset(data);
	}

	chunkqueue_remove_finished_chunks(in);

	return rc;
}

STREAM_IN_OUT_FUNC(proxy_fastcgi_stream_decoder) {
	int res;

	if(out->is_closed) return 1;
	/* decode the whole packet stream */
	do {
		/* decode the packet */
		res = proxy_fastcgi_stream_decoder_internal(srv, sess, in, out);
	} while (in->first && res == 0);

	return res;
}

/**
 * transform the content-stream into a valid FastCGI STDIN content-stream
 *
 * as we don't apply chunked-encoding here, pass it on AS IS
 */
STREAM_IN_OUT_FUNC(proxy_fastcgi_stream_encoder) {
	chunk *c;
	buffer *b;
	FCGI_Header header;
	off_t we_need = 0, we_have = 0;

	UNUSED(srv);
	UNUSED(sess);

	/* there is nothing that we have to send out anymore */
	for (c = in->first; in->bytes_out < in->bytes_in; ) {
		/*
		 * write fcgi header
		 */
		if(we_need == 0) {
			we_need = in->bytes_in - in->bytes_out;
			if(we_need > FCGI_MAX_LENGTH) we_need = FCGI_MAX_LENGTH;

			b = chunkqueue_get_append_buffer(out);
			fcgi_header(&(header), FCGI_STDIN, PROXY_FASTCGI_REQUEST_ID, we_need, 0);
			buffer_copy_memory(b, (const char *)&header, sizeof(header) + 1);
			out->bytes_in += sizeof(header);
		}

		switch (c->type) {
		case FILE_CHUNK:
			we_have = c->file.length - c->offset;
			if (we_have == 0) break;

			if (we_have > we_need) we_have = we_need;

			chunkqueue_append_file(out, c->file.name, c->offset, we_have);

			c->offset += we_have;
			in->bytes_out += we_have;
			out->bytes_in += we_have;
			we_need -= we_have;

			/* steal the tempfile
			 *
			 * This is tricky:
			 * - we reference the tempfile from the in-queue several times
			 *   if the chunk is larger than FCGI_MAX_LENGTH
			 * - we can't simply cleanup the in-queue as soon as possible
			 *   as it would remove the tempfiles
			 * - the idea is to 'steal' the tempfiles and attach the is_temp flag to the last
			 *   referencing chunk of the fastcgi-write-queue
			 *
			 */

			if (c->offset == c->file.length) {
				chunk *out_c;

				out_c = out->last;

				/* the last of the out-queue should be a FILE_CHUNK (we just created it)
				 * and the incoming side should have given use a temp-file-chunk */
				assert(out_c->type == FILE_CHUNK);
				assert(c->file.is_temp == 1);

				out_c->file.is_temp = 1;
				c->file.is_temp = 0;

				c = c->next;
			}

			break;
		case MEM_CHUNK:
			/* append to the buffer */
			we_have = c->mem->used - 1 - c->offset;
			if (we_have == 0) break;

			if (we_have > we_need) we_have = we_need;

			b = chunkqueue_get_append_buffer(out);
			buffer_append_memory(b, c->mem->ptr + c->offset, we_have);
			b->used++; /* add virtual \0 */

			c->offset += we_have;
			in->bytes_out += we_have;
			out->bytes_in += we_have;
			we_need -= we_have;

			if (c->offset == c->mem->used - 1) {
				c = c->next;
			}

			break;
		default:
			break;
		}
	}

	if (in->bytes_in == in->bytes_out && in->is_closed && !out->is_closed) {
		/* send the closing packet */
		b = chunkqueue_get_append_buffer(out);
		/* terminate STDIN */
		fcgi_header(&(header), FCGI_STDIN, PROXY_FASTCGI_REQUEST_ID, 0, 0);
		buffer_copy_memory(b, (const char *)&header, sizeof(header) + 1);

		out->bytes_in += sizeof(header);
		out->is_closed = 1;
	}

	return 0;

}

/**
 * parse the response header
 *
 * - fastcgi needs some decoding for the protocol
 */
STREAM_IN_OUT_FUNC(proxy_fastcgi_parse_response_header) {

	int res;

	res = proxy_fastcgi_stream_decoder(srv, sess, in, out);
	if(res < 0) return res;

	http_response_reset(sess->resp);
	return http_response_parse_cq(out, sess->resp);
}

INIT_FUNC(mod_proxy_backend_fastcgi_init) {
	mod_proxy_core_plugin_data *core_data;
	protocol_plugin_data *p;

	/* get the plugin_data of the core-plugin */
	core_data = plugin_get_config(srv, CORE_PLUGIN);
	if(!core_data) return NULL;

	p = calloc(1, sizeof(*p));

	/* define protocol handler callbacks */
	p->protocol = core_data->proxy_register_protocol("fastcgi");

	p->protocol->proxy_stream_init = proxy_fastcgi_init;
	p->protocol->proxy_stream_cleanup = proxy_fastcgi_cleanup;
	p->protocol->proxy_stream_decoder = proxy_fastcgi_stream_decoder;
	p->protocol->proxy_stream_encoder = proxy_fastcgi_stream_encoder;
	p->protocol->proxy_get_request_chunk = proxy_fastcgi_get_request_chunk;
	p->protocol->proxy_parse_response_header = proxy_fastcgi_parse_response_header;

	return p;
}

int mod_proxy_backend_fastcgi_plugin_init(plugin *p) {
	data_string *ds;

	p->version      = LIGHTTPD_VERSION_ID;
	p->name         = buffer_init_string("mod_proxy_backend_fastcgi");

	p->init         = mod_proxy_backend_fastcgi_init;

	p->data         = NULL;

	ds = data_string_init();
	buffer_copy_string(ds->value, CORE_PLUGIN);
	array_insert_unique(p->required_plugins, (data_unset *)ds);

	return 0;
}
