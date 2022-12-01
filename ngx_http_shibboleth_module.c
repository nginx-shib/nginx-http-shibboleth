
/*
 * Original ngx_http_auth_request module:
 *   Copyright (C) Maxim Dounin
 *   Copyright (C) Nginx, Inc.
 * Forked Shibboleth dedicated module:
 *   Copyright (C) 2013-2016, David Beitey (davidjb)
 *   Copyright (C) 2014, Luca Bruno
 * Contains elements adapted from ngx_lua:
 *   Copyright (C) 2009-2015, by Xiaozhe Wang (chaoslawful) chaoslawful@gmail.com.
 *   Copyright (C) 2009-2015, by Yichun "agentzh" Zhang (章亦春) agentzh@gmail.com, CloudFlare Inc.
 * Contains elements adapted from ngx_headers_more:
 *   Copyright (c) 2009-2017, Yichun "agentzh" Zhang (章亦春) agentzh@gmail.com, OpenResty Inc.
 *   Copyright (c) 2010-2013, Bernd Dorn.
 *
 *  Distributed under 2-clause BSD license, see LICENSE file.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_shib_request_header_val_s  ngx_http_shib_request_header_val_t;

typedef ngx_int_t (*ngx_http_shib_request_set_header_pt)(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);


typedef struct {
    ngx_str_t                               name;
    ngx_uint_t                              offset;
    ngx_http_shib_request_set_header_pt     handler;
} ngx_http_shib_request_set_header_t;


struct ngx_http_shib_request_header_val_s {
    ngx_http_complex_value_t                value;
    ngx_uint_t                              hash;
    ngx_str_t                               key;
    ngx_http_shib_request_set_header_pt     handler;
    ngx_uint_t                              offset;
};


typedef struct {
    ngx_str_t                 uri;
    ngx_array_t              *vars;
    ngx_flag_t                use_headers;
} ngx_http_auth_request_conf_t;


typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
} ngx_http_auth_request_ctx_t;


typedef struct {
    ngx_int_t                 index;
    ngx_http_complex_value_t  value;
    ngx_http_set_variable_pt  set_handler;
} ngx_http_auth_request_variable_t;


static ngx_int_t ngx_http_auth_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_request_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static ngx_int_t ngx_http_auth_request_set_variables(ngx_http_request_t *r,
    ngx_http_auth_request_conf_t *arcf, ngx_http_auth_request_ctx_t *ctx);
static ngx_int_t ngx_http_auth_request_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_auth_request_create_conf(ngx_conf_t *cf);
static char *ngx_http_auth_request_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_request_init(ngx_conf_t *cf);
static char *ngx_http_auth_request(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Functions replicated from ngx_lua */
static ngx_int_t ngx_http_set_output_header(ngx_http_request_t *r,
    ngx_str_t key, ngx_str_t value);
static ngx_int_t ngx_http_set_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_header_helper(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value,
    ngx_table_elt_t **output_header, unsigned no_create);
static ngx_int_t ngx_http_set_builtin_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_builtin_multi_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_last_modified_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_clear_builtin_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_clear_last_modified_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_location_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value);


/* Content-centric headers are ignored from being set since subrequest
 * response bodies aren't currently supported by Nginx.
 */
static ngx_http_shib_request_set_header_t  ngx_http_shib_request_set_handlers[] = {

    { ngx_string("Server"),
                 offsetof(ngx_http_headers_out_t, server),
                 ngx_http_set_builtin_header },

    { ngx_string("Date"),
                 offsetof(ngx_http_headers_out_t, date),
                 ngx_http_set_builtin_header },

    { ngx_string("Content-Encoding"),
                 offsetof(ngx_http_headers_out_t, content_encoding),
                 NULL },

    { ngx_string("Location"),
                 offsetof(ngx_http_headers_out_t, location),
                 ngx_http_set_location_header },

    { ngx_string("Refresh"),
                 offsetof(ngx_http_headers_out_t, refresh),
                 ngx_http_set_builtin_header },

    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_headers_out_t, last_modified),
                 ngx_http_set_last_modified_header },

    { ngx_string("Content-Range"),
                 offsetof(ngx_http_headers_out_t, content_range),
                 NULL },

    { ngx_string("Accept-Ranges"),
                 offsetof(ngx_http_headers_out_t, accept_ranges),
                 ngx_http_set_builtin_header },

    { ngx_string("WWW-Authenticate"),
                 offsetof(ngx_http_headers_out_t, www_authenticate),
                 ngx_http_set_builtin_header },

    { ngx_string("Expires"),
                 offsetof(ngx_http_headers_out_t, expires),
                 ngx_http_set_builtin_header },

    { ngx_string("ETag"),
                 offsetof(ngx_http_headers_out_t, etag),
                 ngx_http_set_builtin_header },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_out_t, content_length),
                 NULL },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_headers_out_t, content_type),
                 NULL },

    { ngx_string("Cache-Control"),
                 offsetof(ngx_http_headers_out_t, cache_control),
                 ngx_http_set_builtin_multi_header },

    { ngx_null_string, 0, ngx_http_set_header }
};


static ngx_command_t  ngx_http_auth_request_commands[] = {

    { ngx_string("shib_request"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("shib_request_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_auth_request_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("shib_request_use_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_request_conf_t, use_headers),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_shibboleth_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_request_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_request_create_conf,     /* create location configuration */
    ngx_http_auth_request_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_shibboleth_module = {
    NGX_MODULE_V1,
    &ngx_http_shibboleth_module_ctx,       /* module context */
    ngx_http_auth_request_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_request_handler(ngx_http_request_t *r)
{
    ngx_uint_t                    i;
    ngx_int_t                     rc;
    ngx_list_part_t               *part;
    ngx_table_elt_t               *h, *hi;
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *ps;
    ngx_http_auth_request_ctx_t   *ctx;
    ngx_http_auth_request_conf_t  *arcf;

    arcf = ngx_http_get_module_loc_conf(r, ngx_http_shibboleth_module);

    if (arcf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "shib request handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_shibboleth_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        /*
         * as soon as we are done - explicitly set variables to make
         * sure they will be available after internal redirects
         */

        if (ngx_http_auth_request_set_variables(r, arcf, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * Handle the subrequest
         * as per the FastCGI authorizer specification.
         */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "shib request authorizer handler");
        sr = ctx->subrequest;

        if (ctx->status == NGX_HTTP_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "shib request authorizer allows access");

            if (arcf->use_headers) {
                /*
                 * 200 response may include headers prefixed with `Variable-`,
                 * copy these into main request headers
                 */
                part = &sr->headers_out.headers.part;
                h = part->elts;

                for (i = 0; /* void */; i++) {

                    if (i >= part->nelts) {
                        if (part->next == NULL) {
                            break;
                        }

                        part = part->next;
                        h = part->elts;
                        i = 0;
                    }

                    if (h[i].hash == 0) {
                        continue;
                    }

                    if (h[i].key.len >= 9 &&
                        ngx_strncasecmp(h[i].key.data, (u_char *) "Variable-", 9) == 0) {
                        /* copy header into original request */
                        hi = ngx_list_push(&r->headers_in.headers);

                        if (hi == NULL) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        /* Strip the Variable- prefix */
                        hi->key.len = h[i].key.len - 9;
                        hi->key.data = h[i].key.data + 9;
                        hi->hash = ngx_hash_key(hi->key.data, hi->key.len);
                        hi->value = h[i].value;

                        hi->lowcase_key = ngx_pnalloc(r->pool, hi->key.len);
                        if (hi->lowcase_key == NULL) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                        ngx_strlow(hi->lowcase_key, hi->key.data, hi->key.len);

                        ngx_log_debug2(
                                NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                "shib request authorizer copied header: \"%V: %V\"",
                                &hi->key, &hi->value);
                    }
                }

            } else {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "shib request authorizer not using headers");
            }


            return NGX_OK;
        }

        /*
         * Unconditionally return subrequest response status, headers
         * and content as per FastCGI spec (section 6.3).
         *
         * The subrequest response body cannot be returned as Nginx does not
         * currently support NGX_HTTP_SUBREQUEST_IN_MEMORY.
         */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "shib request authorizer returning sub-response");

        /* copy status */
        r->headers_out.status = sr->headers_out.status;

        /* copy headers */
        part = &sr->headers_out.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
            }

            rc = ngx_http_set_output_header(r, h[i].key, h[i].value);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            ngx_log_debug2(
              NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "shib request authorizer returning header: \"%V: %V\"",
              &h[i].key, &h[i].value);
        }

        return ctx->status;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_request_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_auth_request_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &arcf->uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    /* 
     * true FastCGI authorizers should always return the subrequest 
     * response body but the Nginx FastCGI handler does not support
     * NGX_HTTP_SUBREQUEST_IN_MEMORY at present.
     */
    sr->header_only = 1;

    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_shibboleth_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_auth_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_auth_request_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "shib request done s:%ui", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static ngx_int_t
ngx_http_auth_request_set_variables(ngx_http_request_t *r,
    ngx_http_auth_request_conf_t *arcf, ngx_http_auth_request_ctx_t *ctx)
{
    ngx_str_t                          val;
    ngx_http_variable_t               *v;
    ngx_http_variable_value_t         *vv;
    ngx_http_auth_request_variable_t  *av, *last;
    ngx_http_core_main_conf_t         *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "shib request set variables");

    if (arcf->vars == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    v = cmcf->variables.elts;

    av = arcf->vars->elts;
    last = av + arcf->vars->nelts;

    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        if (ngx_http_complex_value(ctx->subrequest, &av->value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            /*
             * set_handler only available in cmcf->variables_keys, so we store
             * it explicitly
             */

            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_request_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "shib request variable");

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_http_auth_request_create_conf(ngx_conf_t *cf)
{
    ngx_http_auth_request_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->vars = NGX_CONF_UNSET_PTR;
    conf->use_headers = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_auth_request_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_request_conf_t *prev = parent;
    ngx_http_auth_request_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);
    ngx_conf_merge_value(conf->use_headers, prev->use_headers, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_request_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_request_handler;

    return NGX_OK;
}


static char *
ngx_http_auth_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_request_conf_t *arcf = conf;

    ngx_str_t        *value;

    if (arcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        arcf->uri.len = 0;
        arcf->uri.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    arcf->uri = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_request_conf_t *arcf = conf;

    ngx_str_t                         *value;
    ngx_http_variable_t               *v;
    ngx_http_auth_request_variable_t  *av;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (arcf->vars == NGX_CONF_UNSET_PTR) {
        arcf->vars = ngx_array_create(cf->pool, 1,
                                      sizeof(ngx_http_auth_request_variable_t));
        if (arcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    av = ngx_array_push(arcf->vars);
    if (av == NULL) {
        return NGX_CONF_ERROR;
    }

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    av->index = ngx_http_get_variable_index(cf, &value[1]);
    if (av->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_http_auth_request_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* Implementation adapted from ngx_lua/ngx_http_lua_headers_out.c.
 *
 * Primary difference is that header handling here ignores any headers
 * that have no handler configured, whereas the original code returns
 * an NGX_ERROR.
 */

static ngx_int_t
ngx_http_set_header(ngx_http_request_t *r, ngx_http_shib_request_header_val_t *hv,
    ngx_str_t *value)
{
    return ngx_http_set_header_helper(r, hv, value, NULL, 0);
}


static ngx_int_t
ngx_http_set_header_helper(ngx_http_request_t *r, ngx_http_shib_request_header_val_t *hv,
    ngx_str_t *value, ngx_table_elt_t **output_header,
    unsigned no_create)
{
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;
    unsigned                     matched = 0;

#if 1
    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        /* XXX ngx_http_core_find_config_phase, for example,
         * may not initialize the "key" and "hash" fields
         * for a nasty optimization purpose, and
         * we have to work-around it here */

        r->headers_out.location->hash = ngx_hash_key((u_char *) "location", 8);
        ngx_str_set(&r->headers_out.location->key, "Location");
    }
#endif

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash != 0
            && h[i].key.len == hv->key.len
            && ngx_strncasecmp(hv->key.data, h[i].key.data, h[i].key.len) == 0)
        {

            if (value->len == 0 || matched) {

                h[i].value.len = 0;
                h[i].hash = 0;

            } else {
                h[i].value = *value;
                h[i].hash = hv->hash;
            }

            if (output_header) {
                *output_header = &h[i];
            }

            /* return NGX_OK; */
            matched = 1;
        }
    }

    if (matched) {
        return NGX_OK;
    }

    if (no_create && value->len == 0) {
        return NGX_OK;
    }

    /* XXX we still need to create header slot even if the value
     * is empty because some builtin headers like Last-Modified
     * relies on this to get cleared */

    h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    if (value->len == 0) {
        h->hash = 0;

    } else {
        h->hash = hv->hash;
    }

    h->key = hv->key;
    h->value = *value;
#if defined(nginx_version) && nginx_version >= 1023000
    h->next = NULL;
#endif

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    if (output_header) {
        *output_header = h;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_set_location_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value)
{
    ngx_int_t         rc;
    ngx_table_elt_t  *h;

    rc = ngx_http_set_builtin_header(r, hv, value);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * we do not set r->headers_out.location here to avoid the handling
     * the local redirects without a host name by ngx_http_header_filter()
     */

    h = r->headers_out.location;
    if (h && h->value.len && h->value.data[0] == '/') {
        r->headers_out.location = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_set_builtin_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value)
{
    ngx_table_elt_t  *h, **old;

    if (hv->offset) {
        old = (ngx_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    } else {
        old = NULL;
    }

    if (old == NULL || *old == NULL) {
        return ngx_http_set_header_helper(r, hv, value, old, 0);
    }

    h = *old;

    if (value->len == 0) {
        h->hash = 0;
        h->value = *value;

        return NGX_OK;
    }

    h->hash = hv->hash;
    h->key = hv->key;
    h->value = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_set_builtin_multi_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value)
{
#if defined(nginx_version) && nginx_version >= 1023000
    ngx_table_elt_t  **headers, *h, *ho, **ph;

    headers = (ngx_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    if (*headers) {
        for (h = (*headers)->next; h; h = h->next) {
            h->hash = 0;
            h->value.len = 0;
        }

        h = *headers;

        h->value = *value;

        if (value->len == 0) {
            h->hash = 0;

        } else {
            h->hash = hv->hash;
        }

        return NGX_OK;
    }

    for (ph = headers; *ph; ph = &(*ph)->next) { /* void */ }

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    ho->value = *value;
    ho->hash = hv->hash;
    ngx_str_set(&ho->key, "Cache-Control");
    ho->next = NULL;
    *ph = ho;

    return NGX_OK;
#else
    ngx_array_t      *pa;
    ngx_table_elt_t  *ho, **ph;
    ngx_uint_t        i;

    pa = (ngx_array_t *) ((char *) &r->headers_out + hv->offset);

    if (pa->elts == NULL) {
        if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /* override old values (if any) */

    if (pa->nelts > 0) {
        ph = pa->elts;
        for (i = 1; i < pa->nelts; i++) {
            ph[i]->hash = 0;
            ph[i]->value.len = 0;
        }

        ph[0]->value = *value;

        if (value->len == 0) {
            ph[0]->hash = 0;

        } else {
            ph[0]->hash = hv->hash;
        }

        return NGX_OK;
    }

    ph = ngx_array_push(pa);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    ho->value = *value;

    if (value->len == 0) {
        ho->hash = 0;

    } else {
        ho->hash = hv->hash;
    }

    ho->key = hv->key;
    *ph = ho;

    return NGX_OK;
#endif
}


static ngx_int_t ngx_http_set_last_modified_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value)
{
    if (value->len == 0) {
        return ngx_http_clear_last_modified_header(r, hv, value);
    }

    r->headers_out.last_modified_time = ngx_http_parse_time(value->data,
                                                            value->len);

    return ngx_http_set_builtin_header(r, hv, value);
}


static ngx_int_t
ngx_http_clear_last_modified_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value)
{
    r->headers_out.last_modified_time = -1;

    return ngx_http_clear_builtin_header(r, hv, value);
}


static ngx_int_t
ngx_http_clear_builtin_header(ngx_http_request_t *r,
    ngx_http_shib_request_header_val_t *hv, ngx_str_t *value)
{
    value->len = 0;

    return ngx_http_set_builtin_header(r, hv, value);
}


static ngx_int_t
ngx_http_set_output_header(ngx_http_request_t *r, ngx_str_t key,
    ngx_str_t value)
{
    ngx_http_shib_request_header_val_t         hv;
    ngx_http_shib_request_set_header_t        *handlers = ngx_http_shib_request_set_handlers;
    ngx_uint_t                        i;

    hv.hash = ngx_hash_key_lc(key.data, key.len);
    hv.key = key;

    hv.offset = 0;
    hv.handler = NULL;

    for (i = 0; handlers[i].name.len; i++) {
        if (hv.key.len != handlers[i].name.len
            || ngx_strncasecmp(hv.key.data, handlers[i].name.data,
                               handlers[i].name.len) != 0)
        {
            continue;
        }

        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;

        break;
    }

    if (handlers[i].name.len == 0 && handlers[i].handler) {
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;
    }

    /* if there is no handler, skip the header (eg Content-* headers) */
    if (hv.handler == NULL) {
        return NGX_OK;
    }

    return hv.handler(r, &hv, &value);
}
