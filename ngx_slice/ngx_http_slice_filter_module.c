
/*
 * Copyright (C) cong.zhang@upyun.com(timebug)
 * Copyright (C) yan.sheng@upai.com(cjhust)
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    size_t               size;
    ngx_uint_t           cocurrent;
    ngx_int_t            top_data_index;
} ngx_http_slice_loc_conf_t;


typedef struct {
    ngx_http_request_t  *request;
    off_t                start;
    ngx_uint_t           last_in_chain;
} ngx_http_slice_request_t;


typedef struct {
    ngx_uint_t           init;
    ngx_uint_t           cocurrent;
    ngx_array_t         *requests;        /*ngx_http_slice_request_t*/

    ngx_uint_t           pos;
    ngx_uint_t           next;
    ngx_uint_t           end;
} ngx_http_slice_cocurrent_t;


typedef struct {
    ngx_http_slice_cocurrent_t  cocurrent;

    off_t       offset;
    off_t       start;
    off_t       end;
    off_t       complete_length;
    off_t       slice_size;
    ngx_buf_t   top_data;
    ngx_str_t   range;
    ngx_str_t   etag;
    ngx_uint_t  last;  /* unsigned  last:1; */
} ngx_http_slice_ctx_t;


typedef struct {
    off_t       start;
    off_t       end;
    off_t       complete_length;
} ngx_http_slice_content_range_t;


typedef struct {
    off_t       size;
    off_t       complete_length;
    off_t       slice_size;
} ngx_http_slice_special_header_t;


static void * ngx_http_slice_cocurrent_array_get(ngx_array_t *a, ngx_uint_t i);
static ngx_int_t ngx_http_slice_cocurrent_create_subrequest(ngx_http_request_t *r, ngx_http_slice_ctx_t *ctx, ngx_http_slice_request_t *cr);
static ngx_int_t ngx_http_slice_cocurrent_header_filter(ngx_http_request_t *r, ngx_http_slice_ctx_t *ctx);
static ngx_int_t ngx_http_slice_cocurrent_body_filter(ngx_http_request_t *r, ngx_chain_t *in, ngx_http_slice_ctx_t *ctx);

static ngx_int_t ngx_http_slice_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_slice_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_slice_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags);
static void ngx_http_slice_subrequest_pool_cleanup(void *data);
static void ngx_http_slice_subrequest_pool_reset(void *data);
static off_t ngx_http_slice_get_current_size(ngx_http_request_t *r);
static ngx_int_t ngx_http_slice_parse_special_header(ngx_http_request_t *r,
    ngx_http_slice_special_header_t *sh);
static ngx_int_t ngx_http_slice_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_content_range_t *cr);
static ngx_int_t ngx_http_slice_args_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_slice_size_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static off_t ngx_http_slice_get_start(ngx_http_request_t *r);
static void *ngx_http_slice_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_slice_add_variables(ngx_conf_t *cf);
static char *ngx_http_slice_set_top_data(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_slice_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_slice_filter_commands[] = {

    { ngx_string("slice"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_loc_conf_t, size),
      NULL },

    { ngx_string("slice_cocurrent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_loc_conf_t, cocurrent),
      NULL },

    { ngx_string("slice_set_top_data"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_slice_set_top_data,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_slice_filter_module_ctx = {
    ngx_http_slice_add_variables,          /* preconfiguration */
    ngx_http_slice_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_slice_create_loc_conf,        /* create location configuration */
    ngx_http_slice_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_slice_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_slice_filter_module_ctx,     /* module context */
    ngx_http_slice_filter_commands,        /* module directives */
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


static ngx_str_t  ngx_http_slice_args_name = ngx_string("slice_args");
static ngx_str_t  ngx_http_slice_size_name = ngx_string("slice_size");

static ngx_str_t  ngx_http_slice_size_header = ngx_string("X-Slice-Size");
static ngx_str_t  ngx_http_slice_complete_length_header = ngx_string("X-Slice-Complete-Length");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static void *
ngx_http_slice_cocurrent_array_get(ngx_array_t *a, ngx_uint_t i)
{
    void  *elt;

    if (i >= a->nalloc) {
        return NULL;
    }

    elt = (u_char *) a->elts + a->size * i;
    return elt;
}


static ngx_int_t
ngx_http_slice_cocurrent_create_subrequest(ngx_http_request_t *r, ngx_http_slice_ctx_t *ctx, ngx_http_slice_request_t *csr)
{
    off_t                       end;
    u_char                     *p;
    ngx_str_t                   etag = ngx_null_string;
    ngx_http_request_t         *sr;

    if ((ctx->offset >= ctx->complete_length)
        || (ctx->cocurrent.next >= ctx->cocurrent.end)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected slice cocurrent subrequest: offset = %O, complete_length = %O, next_index = %ui, end_index = %ui",
                      ctx->offset, ctx->complete_length,
                      ctx->cocurrent.next, ctx->cocurrent.end);
        return NGX_ERROR;
    }

    /* just like ngx_http_slice_body_filter */
    if (ngx_http_slice_subrequest(r, &r->uri, &r->args, &sr, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(sr, ctx, ngx_http_slice_filter_module);
    sr->slice_request_index = ctx->cocurrent.next;

    p = ngx_pnalloc(sr->pool, sizeof("_slice_range=-&_slice_etag=")
                        - 1 + 2 * NGX_OFF_T_LEN + 128);
    if (p == NULL) {
        return NGX_ERROR;
    }
    sr->slice_range.data = p;
    sr->slice_range.len = ngx_sprintf(p, "") - p;

    if (ctx->etag.len >= 2 && ctx->etag.data[ctx->etag.len - 1] == '"') {
        etag.data = ctx->etag.data + 1;
        etag.len = ctx->etag.len - 2;
    }

    end = ngx_min(ctx->offset + ctx->slice_size, ctx->complete_length);

    if (etag.len > 0) {
        sr->slice_range.len = ngx_sprintf(sr->slice_range.data,
                                     "_slice_range=%O-%O&_slice_etag=%V", ctx->offset,
                                     end - 1, &etag)
            - sr->slice_range.data;
    } else {
        sr->slice_range.len = ngx_sprintf(sr->slice_range.data,
                                     "_slice_range=%O-%O", ctx->offset,
                                     end - 1)
            - sr->slice_range.data;
    }

    /* store the context of the cocurrent request */
    csr->request = sr;
    csr->last_in_chain = 0;
    csr->start = ctx->offset;

    ctx->offset = end;
    ctx->cocurrent.next++;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http create slice cocurrent subrequest: \"%V\"", &sr->slice_range);

    return NGX_OK;
}


static ngx_int_t
ngx_http_slice_cocurrent_header_filter(ngx_http_request_t *r, ngx_http_slice_ctx_t *ctx)
{
    off_t                            end;
    ngx_int_t                        rc;
    ngx_int_t                        is_ranges;
    ngx_uint_t                       index;
    ngx_table_elt_t                 *h;
    ngx_http_slice_request_t        *csr;
    ngx_http_slice_content_range_t   cr;
    ngx_http_slice_special_header_t  sh;

    /* subrequest only */
    index = r->slice_request_index % ctx->cocurrent.cocurrent;
    csr = (ngx_http_slice_request_t *)ngx_http_slice_cocurrent_array_get(ctx->cocurrent.requests, index);
    if (csr == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected slice_request_index %ui in slice cocurrent header filter",
                      r->slice_request_index);
        return NGX_ERROR;
    }

    is_ranges = 1;
    if (r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || ngx_strncasecmp(r->headers_in.range->value.data,
                           (u_char *) "bytes=", 6)
           != 0)
    {
        is_ranges = 0;
    }

    rc = ngx_http_slice_parse_special_header(r, &sh);
    if (rc != NGX_OK || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    h = r->headers_out.etag;

    if (ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || ngx_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "etag mismatch in slice response");
            return NGX_ERROR;
        }
    }

    if (h && ctx->etag.len == 0) {
        ctx->etag = h->value;
    }

    if (r != r->main) {
        if (ngx_http_slice_parse_content_range(r, &cr) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "invalid range in slice response");
            return NGX_ERROR;
        }

        if (cr.complete_length == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no complete length in slice response");
            return NGX_ERROR;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http slice response range: %O-%O/%O",
                       cr.start, cr.end, cr.complete_length);

        end = ngx_min(cr.start + ctx->slice_size, cr.complete_length);

        /* different from ngx_http_slice_cocurrent_header_filter: cr.start != ctx->start */
        if (cr.start != csr->start || cr.end != end) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "unexpected range in slice response: %O-%O %O-%O",
                          cr.start, cr.end, ctx->start, end);
            return NGX_ERROR;
        }

        ctx->start = end;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_offset = cr.start;

    if (r->headers_out.content_range) {
        r->headers_out.content_range->hash = 0;
        r->headers_out.content_range = NULL;
    }

    r->allow_ranges = 1;
    r->subrequest_ranges = 1;
    r->single_range = 1;

    if (is_ranges == 0) {
        r->allow_ranges = 0;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_slice_cocurrent_body_filter(ngx_http_request_t *r, ngx_chain_t *in, ngx_http_slice_ctx_t *ctx)
{
    ngx_uint_t                  i, index;
    ngx_int_t                   rc;
    ngx_chain_t                *cl;
    ngx_http_slice_request_t   *csr;

    if (r != r->main) {
        index = r->slice_request_index % ctx->cocurrent.cocurrent;
        csr = (ngx_http_slice_request_t *)ngx_http_slice_cocurrent_array_get(ctx->cocurrent.requests, index);
        if (csr == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected index %ui in slice cocurrent body filter", r->slice_request_index);
            return NGX_ERROR;
        }

        for (cl = in; cl; cl = cl->next) {
            if (cl->buf->last_in_chain) {
                cl->buf->slice_subpool = r->pool;
                csr->last_in_chain = 1;
            }
        }

        /* output chain is managed orderly by nginx */
        if (r->slice_request_index != ctx->cocurrent.pos) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "slice subrequest %ui has been advanced in slice cocurrent body filter, pos: %ui, next: %ui, end: %ui", 
                      r->slice_request_index, ctx->cocurrent.pos, ctx->cocurrent.next, ctx->cocurrent.end);

            return ngx_http_next_body_filter(r, in);
        }

        if (csr->last_in_chain == 1) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "slice subrequest %ui send last_chain data in slice cocurrent body filter, pos: %ui, next: %ui, end: %ui", 
                      r->slice_request_index, ctx->cocurrent.pos, ctx->cocurrent.next, ctx->cocurrent.end);

            /* send pos cocurrent sub requests */
            rc = ngx_http_next_body_filter(r, in);
            if (rc == NGX_ERROR) {
                return rc;
            }
            ctx->cocurrent.pos++;

            return rc;
        } else {
            return ngx_http_next_body_filter(r, in);
        }
    }

    /* main request: r == r->main */
    if (r->headers_out.slice_top_data_length) {
        ngx_chain_t out;

        out.buf = &ctx->top_data;
        out.next = NULL;

        rc = ngx_http_next_body_filter(r, &out);
        if (rc == NGX_ERROR) {
            return rc;
        }

        r->headers_out.slice_top_data_length = 0;
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = ngx_http_next_body_filter(r, in);

    if (rc == NGX_ERROR || !ctx->last) {
        return rc;
    }

    /* the last slice piece */
    if ((ctx->cocurrent.pos == ctx->cocurrent.end) && ctx->cocurrent.init) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "slice subrequest send last buf in slice cocurrent body filter");

        r->slice_cocurrent_enable = 0;
        ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
        ngx_http_send_special(r, NGX_HTTP_LAST);
        return rc;
    }

    if (r->buffered) {
        return rc;
    }

    /* create next slice subrequest */
    if (ctx->cocurrent.init) {
        /* create next slice cocurrent subrequests */
        for (i = 0; i < ctx->cocurrent.cocurrent - ctx->cocurrent.next + ctx->cocurrent.pos; i++) {
            if (ctx->cocurrent.next == ctx->cocurrent.end) {
                break;
            }

            index = (ctx->cocurrent.next + i) % ctx->cocurrent.cocurrent;
            csr = (ngx_http_slice_request_t *)ngx_http_slice_cocurrent_array_get(ctx->cocurrent.requests, index);
            if (csr == NULL) {
                return NGX_ERROR;
            }

            if (ngx_http_slice_cocurrent_create_subrequest(r, ctx, csr) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    /* init slice cocurrent requests */
    if (!ctx->cocurrent.init) {
        ctx->cocurrent.init = 1;

        ctx->cocurrent.pos = 0;
        ctx->cocurrent.next = 0;

        if ((ctx->complete_length - ctx->offset) % ctx->slice_size) {
            ctx->cocurrent.end = (ctx->complete_length - ctx->offset) / ctx->slice_size + 1;
        } else {
            ctx->cocurrent.end = (ctx->complete_length - ctx->offset) / ctx->slice_size;
        }

        /* the file is small, adjust cocurrent */
        if (ctx->cocurrent.cocurrent > ctx->cocurrent.end) {
            ctx->cocurrent.cocurrent = ctx->cocurrent.end;
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "[slice] create cocurrent subrequest: cocurrent = %ui, end = %ui", ctx->cocurrent.cocurrent, ctx->cocurrent.end);

        for (i = 0; i < ctx->cocurrent.cocurrent; i++) {
            csr = (ngx_http_slice_request_t *)ngx_http_slice_cocurrent_array_get(ctx->cocurrent.requests, i);
            if (csr == NULL) {
                return NGX_ERROR;
            }

            /* ctx->cocurrent.next++, ctx->offset += ctx->slice_size */
            if (ngx_http_slice_cocurrent_create_subrequest(r, ctx, csr) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return rc;
}


static ngx_int_t
ngx_http_slice_header_filter(ngx_http_request_t *r)
{
    off_t                            end;
    ngx_int_t                        rc;
    ngx_int_t                        is_ranges;
    ngx_table_elt_t                 *h;
    ngx_http_slice_ctx_t            *ctx;
    ngx_http_variable_value_t       *vv;
    ngx_http_slice_loc_conf_t       *slcf;
    ngx_http_slice_content_range_t   cr;
    ngx_http_slice_special_header_t  sh;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if ((ctx->cocurrent.requests != NULL) && (r != r->main)) {
        return ngx_http_slice_cocurrent_header_filter(r, ctx);
    }

    is_ranges = 1;
    if (r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || ngx_strncasecmp(r->headers_in.range->value.data,
                           (u_char *) "bytes=", 6)
           != 0)
    {
        is_ranges = 0;
    }

    rc = ngx_http_slice_parse_special_header(r, &sh);

    if (rc != NGX_OK || r->headers_out.status != NGX_HTTP_OK) {
        if (r == r->main) {
            if (ctx->slice_size > 0 && is_ranges == 1
                && r->headers_out.status == NGX_HTTP_OK) {
                r->allow_ranges = 1;
            }

            ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
            return ngx_http_next_header_filter(r);
        }

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    h = r->headers_out.etag;

    if (ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || ngx_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "etag mismatch in slice response");
            return NGX_ERROR;
        }
    }

    if (h && ctx->etag.len == 0) {
        ctx->etag = h->value;
    }

    if (r == r->main && sh.size > 0 && sh.size != ctx->slice_size) {
        ctx->slice_size = sh.size;
    }

    if (r != r->main) {
        if (ngx_http_slice_parse_content_range(r, &cr) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "invalid range in slice response");
            return NGX_ERROR;
        }

        if (cr.complete_length == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no complete length in slice response");
            return NGX_ERROR;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http slice response range: %O-%O/%O",
                       cr.start, cr.end, cr.complete_length);

        end = ngx_min(cr.start + ctx->slice_size, cr.complete_length);

        if (cr.start != ctx->start || cr.end != end) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "unexpected range in slice response: %O-%O %O-%O",
                          cr.start, cr.end, ctx->start, end);
            return NGX_ERROR;
        }

        ctx->start = end;
    } else {
        cr.start = ctx->start;
        cr.complete_length = sh.complete_length;

        ctx->complete_length = sh.complete_length;
        ctx->offset = ctx->start;
    }

    if (r == r->main) {
        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

        if (slcf->top_data_index != NGX_CONF_UNSET) {

            vv = ngx_http_get_indexed_variable(r, slcf->top_data_index);
            if (vv != NULL && vv->not_found != 1) {
                ctx->top_data.start = vv->data;
                ctx->top_data.pos = vv->data;
                ctx->top_data.last = vv->data + vv->len;
                ctx->top_data.end = vv->data + vv->len;
                ctx->top_data.last_in_chain = 0;
                ctx->top_data.last_buf = 0;
                ctx->top_data.memory = 1;

                r->headers_out.slice_top_data_length = ctx->top_data.end -
                    ctx->top_data.start;
            }
        }
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_offset = cr.start;

    if (r->headers_out.content_range) {
        r->headers_out.content_range->hash = 0;
        r->headers_out.content_range = NULL;
    }

    r->allow_ranges = 1;
    r->subrequest_ranges = 1;
    r->single_range = 1;

    if (is_ranges == 0) {
        r->allow_ranges = 0;
    }

    rc = ngx_http_next_header_filter(r);

    if (r != r->main) {
        return rc;
    }

    if (r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT) {
        if (ctx->start + ctx->slice_size <= r->headers_out.content_offset) {
            ctx->start = ctx->slice_size
                         * (r->headers_out.content_offset / ctx->slice_size);
        }

        ctx->end = r->headers_out.content_offset
                   + r->headers_out.content_length_n;

    } else {
        ctx->end = cr.complete_length;
    }

    return rc;
}


static ngx_int_t
ngx_http_slice_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                       end;
    ngx_int_t                   rc;
    ngx_chain_t                *cl;
    ngx_http_request_t         *sr;
    ngx_http_slice_ctx_t       *ctx;
    ngx_str_t                   etag = ngx_null_string;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->cocurrent.requests != NULL) {
        return ngx_http_slice_cocurrent_body_filter(r, in, ctx);
    }

    if (r != r->main) {
        for (cl = in; cl; cl = cl->next) {
            if (cl->buf->last_in_chain) {
                cl->buf->slice_subpool = r->pool;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    if (r->headers_out.slice_top_data_length) {
        ngx_chain_t out;

        out.buf = &ctx->top_data;
        out.next = NULL;

        rc = ngx_http_next_body_filter(r, &out);
        if (rc == NGX_ERROR) {
            return rc;
        }

        r->headers_out.slice_top_data_length = 0;
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = ngx_http_next_body_filter(r, in);

    if (rc == NGX_ERROR || !ctx->last) {
        return rc;
    }

    if (ctx->start >= ctx->end) {
        ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
        ngx_http_send_special(r, NGX_HTTP_LAST);
        return rc;
    }

    if (r->buffered) {
        return rc;
    }

    if (ngx_http_slice_subrequest(r, &r->uri, &r->args, &sr, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(sr, ctx, ngx_http_slice_filter_module);

    if (ctx->etag.len >= 2 && ctx->etag.data[ctx->etag.len - 1] == '"') {
        etag.data = ctx->etag.data + 1;
        etag.len = ctx->etag.len - 2;
    }

    end = ngx_min(ctx->start + ctx->slice_size, ctx->complete_length);

    if (etag.len > 0) {
        ctx->range.len = ngx_sprintf(ctx->range.data,
                                     "_slice_range=%O-%O&_slice_etag=%V", ctx->start,
                                     end - 1, &etag)
            - ctx->range.data;
    } else {
        ctx->range.len = ngx_sprintf(ctx->range.data,
                                     "_slice_range=%O-%O", ctx->start,
                                     end - 1)
            - ctx->range.data;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice subrequest: \"%V\"", &ctx->range);

    return rc;
}


ngx_int_t
ngx_http_slice_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags)
{
    ngx_pool_t                    *pool;
    ngx_time_t                    *tp;
    ngx_connection_t              *c;
    ngx_pool_cleanup_t            *cln;
    ngx_http_request_t            *sr;
    ngx_http_core_srv_conf_t      *cscf;
    ngx_http_postponed_request_t  *pr, *p;

    if (r->subrequests == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        return NGX_ERROR;
    }

    if (r->main->count >= 65535 - 1000) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "request reference counter overflow "
                      "while processing \"%V\"", uri);
        return NGX_ERROR;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    pool = ngx_create_pool(cscf->request_pool_size, r->connection->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->main->connection->log, 0,
                  "[slice] subrequest create pool: %p", pool);

    sr = ngx_pcalloc(r->main->pool, sizeof(ngx_http_request_t));
    if (sr == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    sr->signature = NGX_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->pool = pool;

    sr->ctx = ngx_pcalloc(sr->pool, sizeof(void *) * ngx_http_max_module);
    if (sr->ctx == NULL) {
        ngx_destroy_pool(sr->pool);
        return NGX_ERROR;
    }

    if (ngx_list_init(&sr->headers_out.headers, sr->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(sr->pool);
        return NGX_ERROR;
    }

    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->headers_in = r->headers_in;

    ngx_http_clear_content_length(sr);
    ngx_http_clear_accept_ranges(sr);
    ngx_http_clear_last_modified(sr);

    sr->request_body = r->request_body;

#if (NGX_HTTP_V2)
    sr->stream = r->stream;
#endif

    sr->method = NGX_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->subrequest_in_memory = (flags & NGX_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited = (flags & NGX_HTTP_SUBREQUEST_WAITED) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = ngx_http_core_get_method;
    sr->http_protocol = r->http_protocol;

    ngx_http_set_exten(sr);

    sr->main = r->main;
    sr->parent = r;
    sr->post_subrequest = ps;
    sr->read_event_handler = ngx_http_request_empty_handler;
    sr->write_event_handler = ngx_http_handler;

    if (c->data == r && r->postponed == NULL) {
        c->data = sr;
    }

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    pr = ngx_palloc(sr->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        ngx_destroy_pool(sr->pool);
        return NGX_ERROR;
    }

    pr->request = sr;
    pr->out = NULL;
    pr->next = NULL;

    if (r->postponed) {
        for (p = r->postponed; p->next; p = p->next) { /* void */ }
        p->next = pr;

    } else {
        r->postponed = pr;
    }

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->expect_tested = 1;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;

    tp = ngx_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count++;

    *psr = sr;

    cln = ngx_pool_cleanup_add(sr->pool, sizeof(ngx_http_request_t));
    if (cln == NULL) {
        ngx_destroy_pool(sr->pool);
        return NGX_ERROR;
    }

    cln->handler = ngx_http_slice_subrequest_pool_reset;
    cln->data = sr;

    cln = ngx_pool_cleanup_add(r->main->pool, sizeof(ngx_http_request_t));
    if (cln == NULL) {
        ngx_destroy_pool(sr->pool);
        return NGX_ERROR;
    }

    cln->handler = ngx_http_slice_subrequest_pool_cleanup;
    cln->data = sr;

    return ngx_http_post_request(sr, NULL);
}


static void
ngx_http_slice_subrequest_pool_cleanup(void *data)
{
    ngx_pool_t                    *pool;
    ngx_http_request_t            *r = data;

    if (r != r->main && r->pool) {
        pool = r->pool;
        r->pool = NULL;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "[slice] subrequest cleanup pool: %p", pool);

        ngx_destroy_pool(pool);
    }
}


static void
ngx_http_slice_subrequest_pool_reset(void *data)
{
    ngx_pool_t                    *pool;
    ngx_http_request_t            *r = data;

    if (r != r->main && r->pool) {
        pool = r->pool;
        r->pool = NULL;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "[slice] subrequest reset pool: %p", pool);
    }
}


static off_t
ngx_http_slice_get_current_size(ngx_http_request_t *r)
{
    off_t                       slice_size;
    ngx_table_elt_t            *h;
    ngx_list_part_t            *part;
    ngx_uint_t                  i;

    slice_size = -1;

    part = &r->headers_in.headers.part;
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

        if (h[i].hash != 0) {
            if (h[i].key.len == ngx_http_slice_size_header.len
                && ngx_strncasecmp(ngx_http_slice_size_header.data,
                                   h[i].key.data, h[i].key.len) == 0) {
                slice_size = ngx_atoof(h[i].value.data, h[i].value.len);
                if (slice_size == NGX_ERROR) {
                    slice_size = -1;
                }
            }
        }

        if (slice_size > 0) {
            break;
        }
    }

    return slice_size;
}


static ngx_int_t
ngx_http_slice_parse_special_header(ngx_http_request_t *r,
    ngx_http_slice_special_header_t *sh)
{
    off_t                       size, complete_length;
    ngx_table_elt_t            *h;
    ngx_list_part_t            *part;
    ngx_uint_t                  i;

    part = &r->headers_out.headers.part;
    h = part->elts;

    size = -1;
    complete_length = -1;

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

        if (h[i].hash != 0) {
            if (h[i].key.len == ngx_http_slice_size_header.len
                && ngx_strncasecmp(ngx_http_slice_size_header.data,
                                   h[i].key.data, h[i].key.len) == 0) {
                size = ngx_atoof(h[i].value.data, h[i].value.len);
                if (size == NGX_ERROR) {
                    size = -1;
                }
            }

            if (h[i].key.len == ngx_http_slice_complete_length_header.len
                && ngx_strncasecmp(ngx_http_slice_complete_length_header.data,
                                   h[i].key.data, h[i].key.len) == 0) {
                complete_length = ngx_atoof(h[i].value.data, h[i].value.len);
                if (complete_length == NGX_ERROR) {
                    complete_length = -1;
                }
            }

            if (size > 0 && complete_length > 0) {
                break;
            }
        }
    }

    sh->size = size;
    sh->complete_length = complete_length;

    if (size == -1) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_slice_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_content_range_t *cr)
{
    off_t             start, end, complete_length, cutoff, cutlim;
    u_char           *p;
    ngx_table_elt_t  *h;

    h = r->headers_out.content_range;

    if (h == NULL
        || h->value.len < 7
        || ngx_strncmp(h->value.data, "bytes ", 6) != 0)
    {
        return NGX_ERROR;
    }

    p = h->value.data + 6;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    complete_length = 0;

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        start = start * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        end = end * 10 + *p++ - '0';
    }

    end++;

    while (*p == ' ') { p++; }

    if (*p++ != '/') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p != '*') {
        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }

        while (*p >= '0' && *p <= '9') {
            if (complete_length >= cutoff
                && (complete_length > cutoff || *p - '0' > cutlim))
            {
                return NGX_ERROR;
            }

            complete_length = complete_length * 10 + *p++ - '0';
        }

    } else {
        complete_length = -1;
        p++;
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return NGX_ERROR;
    }

    cr->start = start;
    cr->end = end;
    cr->complete_length = complete_length;

    return NGX_OK;
}


static ngx_int_t
ngx_http_slice_args_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_http_slice_ctx_t       *ctx;
    ngx_http_slice_loc_conf_t  *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);

    if (ctx == NULL) {
        if (r != r->main || r->headers_out.status) {
            v->not_found = 1;
            return NGX_OK;
        }

        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);
        if (slcf->size == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_slice_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_slice_filter_module);

        if (slcf->cocurrent > 0) {
            ctx->cocurrent.requests = ngx_array_create(r->pool, slcf->cocurrent, sizeof(ngx_http_slice_request_t));
            if (ctx->cocurrent.requests == NULL) {
                return NGX_ERROR;
            }

            ctx->cocurrent.cocurrent = slcf->cocurrent;
        }

        p = ngx_pnalloc(r->pool, sizeof("_slice_range=-&_slice_etag=")
                        - 1 + 2 * NGX_OFF_T_LEN + 128);
        if (p == NULL) {
            return NGX_ERROR;
        }

        r->slice_range.data = p;
        r->slice_range.len = ngx_sprintf(p, "") - p;

        ctx->range.data = p;
        ctx->range.len = ngx_sprintf(p, "") - p;
    }

    if (r == r->main) {
        ctx->slice_size = ngx_http_slice_get_current_size(r);
        if (ctx->slice_size <= 0) {
            ctx->start = 0;
        } else {
            ctx->start = ctx->slice_size * (ngx_http_slice_get_start(r) / ctx->slice_size);
        }
    }

    if (ctx->cocurrent.requests == NULL) {
        v->data = ctx->range.data;
        v->len = ctx->range.len;
    } else {
        v->data = r->slice_range.data;
        v->len = r->slice_range.len;
        r->slice_cocurrent_enable = 1;
    }

    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_slice_size_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    off_t                       size;
    ngx_http_slice_ctx_t       *ctx;
    ngx_http_slice_loc_conf_t  *slcf;

    size = -1;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);

    if (ctx == NULL || ctx->slice_size <= 0) {
        if (r != r->main || r->headers_out.status) {
            v->not_found = 1;
            return NGX_OK;
        }

        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

        if (slcf->size == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        size = (off_t) slcf->size;
    } else {
        size = ctx->slice_size;
    }

    v->data = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%O", size) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static off_t
ngx_http_slice_get_start(ngx_http_request_t *r)
{
    off_t             start, cutoff, cutlim;
    u_char           *p;
    ngx_table_elt_t  *h;

    if (r->headers_in.if_range) {
        return 0;
    }

    h = r->headers_in.range;

    if (h == NULL
        || h->value.len < 7
        || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return 0;
    }

    p = h->value.data + 6;

    if (ngx_strchr(p, ',')) {
        return 0;
    }

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return 0;
    }

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return 0;
        }

        start = start * 10 + *p++ - '0';
    }

    return start;
}


static void *
ngx_http_slice_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_slice_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_slice_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->size = NGX_CONF_UNSET_SIZE;
    slcf->cocurrent = NGX_CONF_UNSET_UINT;
    slcf->top_data_index = NGX_CONF_UNSET;

    return slcf;
}


static char *
ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_slice_loc_conf_t *prev = parent;
    ngx_http_slice_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->size, prev->size, 0);
    ngx_conf_merge_uint_value(conf->cocurrent, prev->cocurrent, 0);
    if (conf->cocurrent > 64) {
        conf->cocurrent = 64;
    }

    if (conf->top_data_index == NGX_CONF_UNSET) {
        conf->top_data_index = prev->top_data_index;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_slice_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_slice_args_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_slice_args_variable;

    var = ngx_http_add_variable(cf, &ngx_http_slice_size_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_slice_size_variable;

    return NGX_OK;
}


static char *
ngx_http_slice_set_top_data(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value;
    ngx_http_variable_t               *v;
    ngx_http_slice_loc_conf_t         *slcf;

    slcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_slice_filter_module);

    value = cf->args->elts;

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    slcf->top_data_index = ngx_http_get_variable_index(cf, &value[1]);
    if (slcf->top_data_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_slice_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_slice_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_slice_body_filter;

    return NGX_OK;
}
