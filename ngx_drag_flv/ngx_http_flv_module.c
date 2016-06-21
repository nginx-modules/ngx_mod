
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_FLV_HEADER_SIZE                      9
#define NGX_HTTP_FLV_PREVIOUS_TAG_SIZE                4
#define NGX_HTTP_FLV_TAG_HEADER_SIZE                  11
#define NGX_HTTP_FLV_TAG_HEADER_TIMESTAMP_OFFSET      4


#define NGX_HTTP_FLV_AUDIO_TYPT                       0x8
#define NGX_HTTP_FLV_VIDEO_TYPT                       0x9
#define NGX_HTTP_FLV_SCRIPT_TYPT                      0x12
#define NGX_HTTP_FLV_VIDEO_AVC_TYPE                   0x7


#define NGX_HTTP_FLV_SCRIPT_FIRST_AMF_HEADER_SIZE     13
#define NGX_HTTP_FLV_SCRIPT_SECOND_AMF_HEADER_SIZE    5


typedef enum {
    NGX_HTTP_FLV_SCRIPT_TAG_NUMBER_TYPE        =      0x0,
    NGX_HTTP_FLV_SCRIPT_TAG_BOOLEAN_TYPE       =      0x1,
    NGX_HTTP_FLV_SCRIPT_TAG_STRING_TYPE        =      0x2,
    NGX_HTTP_FLV_SCRIPT_TAG_OBJECT_TYPE        =      0x3,
    NGX_HTTP_FLV_SCRIPT_TAG_ARRAY_TYPE         =      0x8,
    NGX_HTTP_FLV_SCRIPT_TAG_OBJECT_END_TYPE    =      0x9,
    NGX_HTTP_FLV_SCRIPT_TAG_STRICT_ARRAY_TYPE  =      0xa,
    NGX_HTTP_FLV_SCRIPT_TAG_DATE_TYPE          =      0x0b,
} NGX_HTTP_FLV_AMF_DATA_TYPE;


typedef struct {
    size_t                max_buffer_size;
} ngx_http_flv_conf_t;


typedef struct {
    u_char                type;
    u_char                datasize[3];
    u_char                timestamp[3];
    u_char                extend_timestamp;
    u_char                stream[3];
} ngx_flv_tag_header_t;


typedef struct {
    u_char                frametype[4];
    u_char                codecID[4];       /* H.263 or AVC(H.264)... */
} ngx_flv_video_tag_header_t;


typedef struct {
    u_char                format[4];        /* MP3 or AAC ...*/
    u_char                rate[2];          /* 5.5kHz or 11kHz ...*/
    u_char                size;             /* 8-bit or 16-bit */
    u_char                type;             /* Mono or Stereo ... */
} ngx_flv_audio_tag_header_t;


typedef struct {
    ngx_log_t            *log;

    u_char               *buffer_start;
    u_char               *buffer_pos;
    u_char               *buffer_end;
    u_char               *buffer_metadata_start;  /* start of data*/
    u_char               *buffer_metadata_end;    /* end of data*/

    ngx_uint_t            start;
    off_t                 end;
    double                duration;
    double                start_timestamp;
    off_t                 start_offset;
    off_t                 end_offset;
    ngx_uint_t            start_frame_index;
    ngx_uint_t            end_frame_index;
    off_t                 offset;
    off_t                 content_length;

    ngx_http_request_t   *request;

    ngx_array_t          *metadata_filepositions;
    ngx_array_t          *metadata_times;

    ngx_chain_t          *out;
    ngx_chain_t           header_tag;
    ngx_chain_t           tailer_tag;
    ngx_chain_t           metadata_tag;
    ngx_chain_t           video_tag;
    ngx_chain_t           audio_tag;

    ngx_buf_t             header_tag_buf;
    ngx_buf_t             tailer_tag_buf;
    ngx_buf_t             metadata_tag_buf;
    ngx_buf_t             video_tag_buf;
    ngx_buf_t             audio_tag_buf;

    /*
     *tag_size = tag_header(11) + data_size + pre_header_size(4)
     */
    size_t                metadata_tag_size;
    size_t                video_tag_size;
    size_t                audio_tag_size;

    uint8_t               video_format;
    uint8_t               audio_format;

    unsigned              metadata_parsed:1;
    unsigned              video_parsed:1;
    unsigned              audio_parsed:1;
} ngx_http_flv_file_t;


#define ngx_flv_tag_next(flv, n)                                              \
    flv->buffer_pos += (size_t) n;                                            \
    flv->offset += n


#define ngx_flv_get_8value(p)                                                 \
     ( ((uint8_t) ((u_char *) (p))[0] ) )


#define ngx_flv_set_8value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((uint8_t)  (n))


#define ngx_flv_get_16value(p)                                                \
    ( ((uint16_t) ((u_char *) (p))[0] << 8)                                   \
    + (           ((u_char *) (p))[1]) )


#define ngx_flv_set_16value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((uint16_t) (n) >> 8);                    \
    ((u_char *) (p))[1] = (u_char)             (n)


#define ngx_flv_get_24value(p)                                                \
    ( ((uint32_t) 0)                                                          \
    + (           ((u_char *) (p))[0] << 16)                                  \
    + (           ((u_char *) (p))[1] << 8)                                   \
    + (           ((u_char *) (p))[2]) )


#define ngx_flv_set_24value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((n) >> 16);                               \
    ((u_char *) (p))[1] = (u_char) ((n) >> 8);                               \
    ((u_char *) (p))[2] = (u_char)  (n)


#define ngx_flv_get_32value(p)                                                \
    ( ((uint32_t) ((u_char *) (p))[0] << 24)                                  \
    + (           ((u_char *) (p))[1] << 16)                                  \
    + (           ((u_char *) (p))[2] << 8)                                   \
    + (           ((u_char *) (p))[3]) )


#define ngx_flv_set_32value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((n) >> 24);                               \
    ((u_char *) (p))[1] = (u_char) ((n) >> 16);                               \
    ((u_char *) (p))[2] = (u_char) ((n) >> 8);                                \
    ((u_char *) (p))[3] = (u_char)  (n)


#define ngx_flv_set_timestamp(p, n)                                           \
    ((u_char *) (p))[3] = (u_char) ((n) >> 24);                               \
    ((u_char *) (p))[0] = (u_char) ((n) >> 16);                               \
    ((u_char *) (p))[1] = (u_char) ((n) >> 8);                                \
    ((u_char *) (p))[2] = (u_char)  (n)


static u_char  ngx_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";


static ngx_int_t ngx_http_flv_buf_read(ngx_http_flv_file_t *flv, size_t size);
static ngx_buf_t *ngx_http_flv_read_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_flv_validate_header(ngx_http_flv_file_t *flv);
static ngx_int_t ngx_http_flv_parse_metadata_strict_array_type(ngx_http_flv_file_t *flv, ngx_uint_t size, ngx_array_t *array);

static ngx_int_t ngx_http_flv_parse_metadata_array_type(ngx_http_flv_file_t *flv, ngx_uint_t size);
static ngx_int_t ngx_http_flv_parse_metadata_tag(ngx_http_flv_file_t *flv, uint32_t tag_data_size);
static ngx_int_t ngx_http_flv_parse_video_tag(ngx_http_flv_file_t *flv, uint32_t tag_data_size);
static ngx_int_t ngx_http_flv_parse_audio_tag(ngx_http_flv_file_t *flv, uint32_t tag_data_size);
static void ngx_flv_metadata_write_double(ngx_buf_t *buf, double value);
static void ngx_flv_metadata_write_keyframes_array(ngx_http_flv_file_t *flv, ngx_buf_t *buf, ngx_array_t *array, ngx_str_t *name, off_t adjustment);
static void ngx_flv_metadata_write_array_end(ngx_buf_t *buf);
static ngx_int_t ngx_http_flv_package_metadata(ngx_http_flv_file_t *flv);
static ngx_int_t ngx_http_flv_buf_read_tag(ngx_http_flv_file_t *flv);
static void ngx_http_flv_set_tag_timestamp(ngx_http_flv_file_t *flv, ngx_buf_t *tag, double start_timestamp);
static void ngx_http_flv_process_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_flv_compute_offset_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_flv_handler(ngx_http_request_t *r);
static void *ngx_http_flv_create_conf(ngx_conf_t *cf);
static char *ngx_http_flv_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_flv_compute_offset(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_flv_commands[] = {

    { ngx_string("flv"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_flv,
      0,
      0,
      NULL },

    { ngx_string("flv_compute_offset"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_flv_compute_offset,
      0,
      0,
      NULL },

    { ngx_string("flv_max_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_conf_t, max_buffer_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_flv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_flv_create_conf,      /* create location configuration */
    ngx_http_flv_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_flv_module = {
    NGX_MODULE_V1,
    &ngx_http_flv_module_ctx,      /* module context */
    ngx_http_flv_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_flv_buf_read(ngx_http_flv_file_t *flv, size_t size)
{
    if (flv->buffer_pos + size <= flv->buffer_end) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_buf_t *
ngx_http_flv_read_body(ngx_http_request_t *r)
{
    size_t                len;
    ssize_t               size;
    ngx_buf_t            *buf, *body;
    ngx_chain_t          *cl;
    ngx_http_flv_conf_t  *conf;

    len = 0;
    cl = r->request_body->bufs;

    while (cl) {

        buf = cl->buf;

        if (buf->in_file) {
            len += buf->file_last - buf->file_pos;
        } else {
            len += buf->last - buf->pos;
        }

        cl = cl->next;
    }

    if (len == 0) {
        return NULL;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_flv_module);
    if (len > conf->max_buffer_size) {
        return NULL;
    }

    body = ngx_create_temp_buf(r->pool, len);
    if (body == NULL) {
        return NULL;
    }

    cl = r->request_body->bufs;

    while (cl) {

        buf = cl->buf;

        if (buf->in_file) {

            size = ngx_read_file(buf->file, body->last,
                                 buf->file_last - buf->file_pos, buf->file_pos);

            if (size == NGX_ERROR) {
                return NULL;
            }

            body->last += size;

        } else {

            body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
        }

        cl = cl->next;
    }

    return body;
}


static ngx_int_t
ngx_http_flv_validate_header(ngx_http_flv_file_t *flv)
{
    u_char                *header;

    if (ngx_http_flv_buf_read(flv, NGX_HTTP_FLV_HEADER_SIZE + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_validate_header: buffer size too small");

        return NGX_ERROR;
    }

    header = flv->buffer_pos;

    if (ngx_strncmp(header, "FLV", 3) != 0) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_validate_header: bad FLV file");

        return NGX_ERROR;
    }

    if (ngx_flv_get_8value(&header[3]) != 1) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_validate_header: bad version");

        return NGX_ERROR;
    }

    if (ngx_flv_get_32value(&header[5]) != NGX_HTTP_FLV_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_validate_header: bad header size");

        return NGX_ERROR;
    }

    ngx_flv_tag_next(flv, NGX_HTTP_FLV_HEADER_SIZE + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE);

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_parse_metadata_strict_array_type(ngx_http_flv_file_t *flv, ngx_uint_t size, ngx_array_t *array)
{
    ngx_uint_t      i, offset;
    double          *node;
    uint8_t         type;
    u_char         *header, *pos, *end;
    ngx_str_t       value;
    union {
        u_char      dc[8];
        double      dd;
    } doublevalue;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->log, 0, "parse flv metadata strict array tag");

    offset = 0;
    pos = flv->buffer_pos;
    end = flv->buffer_metadata_end;
    for (i = 0; i < size; i++) {
         header = pos + offset;
         if (end - header < 1) {
             return NGX_ERROR;
         }
         type = ngx_flv_get_8value(header);

         offset += 1;
         header = pos + offset;
         switch (type) {
             case NGX_HTTP_FLV_SCRIPT_TAG_NUMBER_TYPE:
                 if (end - header < 8) {
                    return NGX_ERROR;
                 }
                 doublevalue.dc[0] = header[7];
                 doublevalue.dc[1] = header[6];
                 doublevalue.dc[2] = header[5];
                 doublevalue.dc[3] = header[4];
                 doublevalue.dc[4] = header[3];
                 doublevalue.dc[5] = header[2];
                 doublevalue.dc[6] = header[1];
                 doublevalue.dc[7] = header[0];

                 if (array != NULL) {
                     node = ngx_array_push(array);
                     *node = doublevalue.dd;
                 }
                 offset += 8;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_BOOLEAN_TYPE:
                 if (end - header < 1) {
                    return NGX_ERROR;
                 }

                 offset += 1;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_STRING_TYPE:
                 if (end - header < 2) {
                     return NGX_ERROR;
                 }
                 value.len = ngx_flv_get_16value(header);
                 value.data = header + 2;

                 offset += 2 + value.len;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_DATE_TYPE:
                 if (end - header < 10) {
                    return NGX_ERROR;
                 }

                 offset += 10;
                 continue;

             default:
                 ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_strict_array_type: unkown type %ui", type);
                 return NGX_ERROR;
         }
    }

    ngx_flv_tag_next(flv, offset);

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_parse_metadata_array_type(ngx_http_flv_file_t *flv, ngx_uint_t size)
{
    ngx_int_t       rc;
    ngx_uint_t      offset, end_flag;
    u_char         *header, *pos, *end;
    ngx_str_t       key, value;
    uint8_t         type, boolvalue;
    union {
        u_char      dc[8];
        double      dd;
    } doublevalue;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->log, 0, "parse flv metadata array tag");

    end_flag = 0;
    offset = 0;
    pos = flv->buffer_pos;
    end = flv->buffer_metadata_end;
    while(1) {

         header = pos + offset;
         if (end == header) {
             break;
         }

         if (end - header < 2) {
             return NGX_ERROR;
         }
         key.len = ngx_flv_get_16value(header);
         key.data = header + 2;

         offset += 2 + key.len;
         header = pos + offset;
         if (end - header < 1) {
             return NGX_ERROR;
         }
         type = ngx_flv_get_8value(header);

         offset += 1;
         header = pos + offset;
         switch (type) {
             case NGX_HTTP_FLV_SCRIPT_TAG_NUMBER_TYPE:
                 if (end - header < 8) {
                    return NGX_ERROR;
                 }
                 doublevalue.dc[0] = header[7];
                 doublevalue.dc[1] = header[6];
                 doublevalue.dc[2] = header[5];
                 doublevalue.dc[3] = header[4];
                 doublevalue.dc[4] = header[3];
                 doublevalue.dc[5] = header[2];
                 doublevalue.dc[6] = header[1];
                 doublevalue.dc[7] = header[0];

                 if ((key.len == 8) && (ngx_strncmp("duration", key.data, key.len) == 0)) {
                     flv->duration = doublevalue.dd;
                 }

                 ngx_log_error(NGX_LOG_INFO, flv->log, 0,
                          "ngx_http_flv_parse_metadata_array_type: key = %V, value = %.1f",
                          &key, doublevalue.dd);

                 offset += 8;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_BOOLEAN_TYPE:
                 if (end - header < 1) {
                    return NGX_ERROR;
                 }
                 boolvalue = ngx_flv_get_8value(header);

                 ngx_log_error(NGX_LOG_INFO, flv->log, 0,
                          "ngx_http_flv_parse_metadata_array_type: key = %V, value = %ui",
                          &key, boolvalue);

                 offset += 1;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_STRING_TYPE:
                 if (end - header < 2) {
                     return NGX_ERROR;
                 }
                 value.len = ngx_flv_get_16value(header);
                 value.data = header + 2;

                 ngx_log_error(NGX_LOG_INFO, flv->log, 0,
                          "ngx_http_flv_parse_metadata_array_type: key = %V, value = %V",
                          &key, &value);

                 offset += 2 + value.len;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_DATE_TYPE:
                 if (end - header < 10) {
                    return NGX_ERROR;
                 }

                 offset += 10;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_OBJECT_TYPE:
                 end_flag += 1;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_STRICT_ARRAY_TYPE:
                 if (end - header < 4) {
                     return NGX_ERROR;
                 }
                 value.len = ngx_flv_get_32value(header);
                 offset += 4;
                 ngx_flv_tag_next(flv, offset);

                 if ((key.len == 5)
                     && ngx_strncmp("times", key.data, key.len) == 0) {

                     rc = ngx_http_flv_parse_metadata_strict_array_type(flv, value.len, flv->metadata_times);

                 } else if ((key.len == 13)
                     && ngx_strncmp("filepositions", key.data, key.len) == 0) {

                     rc = ngx_http_flv_parse_metadata_strict_array_type(flv, value.len, flv->metadata_filepositions);

                 } else {

                     rc = ngx_http_flv_parse_metadata_strict_array_type(flv, value.len, NULL);

                 }

                 if (rc != NGX_OK) {
                     return rc;
                 }
                 offset = 0;
                 pos = flv->buffer_pos;
                 continue;

             case NGX_HTTP_FLV_SCRIPT_TAG_OBJECT_END_TYPE:
                 if (end_flag == 0) {
                    break;
                 }

                 end_flag -= 1;
                 continue;

             default:
                 ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_array_type: unkown type %ui, key = %V", type, &key);

                 return NGX_ERROR;
         }
    }

    if (end_flag != 0) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_array_type: end flag not equals zero");

        return NGX_ERROR;
    }

    ngx_flv_tag_next(flv, offset);

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_parse_metadata_tag(ngx_http_flv_file_t *flv, uint32_t tag_data_size)
{
    ngx_int_t                         rc;
    ngx_uint_t                        i;
    double                           *node;
    ngx_buf_t                        *tag;
    u_char                           *header;
    uint8_t                           type;
    uint16_t                          length;

    flv->metadata_parsed = 1;
    flv->metadata_tag_size = tag_data_size + NGX_HTTP_FLV_TAG_HEADER_SIZE + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE;

    tag = &flv->metadata_tag_buf;
    tag->memory = 1;
    tag->pos = flv->buffer_pos - NGX_HTTP_FLV_TAG_HEADER_SIZE;
    tag->last = flv->buffer_pos + tag_data_size + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE;

    flv->metadata_tag.next = NULL;
    flv->metadata_tag.buf = tag;
    flv->buffer_metadata_start = flv->buffer_pos;
    flv->buffer_metadata_end = flv->buffer_pos + tag_data_size;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->log, 0, "parse flv metadata tag");

    if (tag_data_size < NGX_HTTP_FLV_SCRIPT_FIRST_AMF_HEADER_SIZE + NGX_HTTP_FLV_SCRIPT_SECOND_AMF_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_tag: datasize too small %ui", tag_data_size);

        return NGX_ERROR;
    }

    /*
     * first AMF packet
     */
    header = flv->buffer_pos;
    type = ngx_flv_get_8value(header);
    length = ngx_flv_get_16value(header + 1);

    if (type != NGX_HTTP_FLV_SCRIPT_TAG_STRING_TYPE) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_tag: bad type %ui", type);

        return NGX_ERROR;
    }

    if (length != 10) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_tag: bad length %ui", length);

        return NGX_ERROR;
    }

    if (ngx_strncmp(header + 3, "onMetaData", length) != 0) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_tag: bad string");

        return NGX_ERROR;
    }

    ngx_flv_tag_next(flv, NGX_HTTP_FLV_SCRIPT_FIRST_AMF_HEADER_SIZE);

    /*
     * second AMF packet
     */
    header = flv->buffer_pos;
    type = ngx_flv_get_8value(header);
    length = ngx_flv_get_32value(header + 1);

    if (type != NGX_HTTP_FLV_SCRIPT_TAG_ARRAY_TYPE) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                      "ngx_http_flv_parse_metadata_tag: bad array type");

        return NGX_ERROR;
    }

    ngx_flv_tag_next(flv, NGX_HTTP_FLV_SCRIPT_SECOND_AMF_HEADER_SIZE);

    /*
     * onMetaData
     */
    flv->metadata_filepositions = ngx_array_create(flv->request->pool, 10, sizeof(double *));
    if (flv->metadata_filepositions == NULL) {
        return NGX_ERROR;
    }

    flv->metadata_times = ngx_array_create(flv->request->pool, 10, sizeof(double *));
    if (flv->metadata_times == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_flv_parse_metadata_array_type(flv, length);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_flv_tag_next(flv, NGX_HTTP_FLV_PREVIOUS_TAG_SIZE);

    /*
     * compute nearest offset and times
    */
    if ((flv->metadata_filepositions->nelts != flv->metadata_times->nelts)
       || (flv->metadata_filepositions->nelts == 0)) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                          "ngx_http_flv_parse_metadata_tag: filepositions.nelts = %ui, times.nelts = %ui, not equal or zero",
                          flv->metadata_filepositions->nelts, flv->metadata_times->nelts);

        return NGX_ERROR;
    }

    node = flv->metadata_filepositions->elts;
    flv->end_frame_index = flv->metadata_filepositions->nelts - 1;
    flv->end_offset = node[flv->end_frame_index];
    for (i = 0; i < flv->metadata_filepositions->nelts; i++) {

        if (node[i] <= flv->start) {
            flv->start_offset = (ngx_uint_t)node[i];
            flv->start_frame_index = i;
        } else {

            if (i == 0) {
                flv->start_offset = (ngx_uint_t)node[i];
                flv->start_frame_index = i;
            }

            if (flv->end == -1) {
                break;
            }
        }

        if ((flv->end != -1) && (node[i] >= flv->end)) {
            flv->end_offset = (ngx_uint_t)node[i];
            flv->end_frame_index = i;
            break;
        }
    }

    if ((flv->start_offset == -1) || (flv->end_offset == -1)) {
        ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                          "ngx_http_flv_parse_metadata_tag: can't find nearest offset, args_start_offset = %O, args_end_offset = %O",
                          flv->start, flv->end);

        return NGX_ERROR;
    }

    if (flv->start_frame_index >= flv->metadata_times->nelts) {
        return NGX_ERROR;
    }

    node = flv->metadata_times->elts;
    flv->start_timestamp = node[flv->start_frame_index];

    if ((flv->end == -1) && (flv->duration != 0)) {
        flv->duration -= flv->start_timestamp;
    } else {
        flv->duration = node[flv->end_frame_index] - node[flv->start_frame_index];
    }

    ngx_log_error(NGX_LOG_INFO, flv->log, 0,
                          "ngx_http_flv_parse_metadata_tag: find nearest offset and timestamp, args_start_offset = %O, compute_offset = %O, start_timestamp = %.1f",
                          flv->start, flv->start_offset, flv->start_timestamp);

    if (flv->start != (ngx_uint_t)flv->start_offset) {
        ngx_log_error(NGX_LOG_WARN, flv->log, 0,
                      "ngx_http_flv_parse_metadata_tag: adjust start offset from %O to %O", flv->start, flv->start_offset);

        flv->start = flv->start_offset;
    }

    if ((flv->end != -1) && (flv->end != flv->end_offset)) {
        ngx_log_error(NGX_LOG_WARN, flv->log, 0,
                      "ngx_http_flv_parse_metadata_tag: adjust end offset from %O to %O", flv->end, flv->end_offset);

        flv->end = flv->end_offset;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_parse_video_tag(ngx_http_flv_file_t *flv, uint32_t tag_data_size)
{
    uint8_t                           flags;
    ngx_buf_t                        *tag;
    ngx_flv_video_tag_header_t       *header;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->log, 0, "parse flv video tag");

    header = (ngx_flv_video_tag_header_t *)flv->buffer_pos;

    if (tag_data_size < 1) {
        return NGX_ERROR;
    }
    flags = ngx_flv_get_8value(header);

    flv->video_format = flags & 0xf;
    flv->video_tag_size = tag_data_size + NGX_HTTP_FLV_TAG_HEADER_SIZE + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE;
    flv->video_parsed = 1;

    tag = &flv->video_tag_buf;
    tag->memory = 1;
    tag->pos = flv->buffer_pos - NGX_HTTP_FLV_TAG_HEADER_SIZE;
    tag->last = flv->buffer_pos + tag_data_size + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE;

    flv->video_tag.next = NULL;
    flv->video_tag.buf = tag;

    ngx_flv_tag_next(flv, tag_data_size + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE);

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_parse_audio_tag(ngx_http_flv_file_t *flv, uint32_t tag_data_size)
{
    uint8_t                           flags;
    ngx_buf_t                        *tag;
    ngx_flv_audio_tag_header_t       *header;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->log, 0, "parse flv audio tag");

    header = (ngx_flv_audio_tag_header_t *)flv->buffer_pos;

    if (tag_data_size < 1) {
        return NGX_ERROR;
    }
    flags = ngx_flv_get_8value(header);

    flv->audio_format = (flags >> 4) & 0xf;
    flv->audio_tag_size = tag_data_size + NGX_HTTP_FLV_TAG_HEADER_SIZE + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE;
    flv->audio_parsed = 1;

    tag = &flv->audio_tag_buf;
    tag->memory = 1;
    tag->pos = flv->buffer_pos - NGX_HTTP_FLV_TAG_HEADER_SIZE;
    tag->last = flv->buffer_pos + tag_data_size + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE;

    flv->audio_tag.next = NULL;
    flv->audio_tag.buf = tag;

    ngx_flv_tag_next(flv, tag_data_size + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE);

    return NGX_OK;
}


static void
ngx_flv_metadata_write_double(ngx_buf_t *buf, double value)
{
    union {
        u_char dc[8];
        double dd;
    } d;
    u_char b[8];

    d.dd = value;
    b[0] = d.dc[7];
    b[1] = d.dc[6];
    b[2] = d.dc[5];
    b[3] = d.dc[4];
    b[4] = d.dc[3];
    b[5] = d.dc[2];
    b[6] = d.dc[1];
    b[7] = d.dc[0];

    ngx_flv_set_8value(buf->last, NGX_HTTP_FLV_SCRIPT_TAG_NUMBER_TYPE);
    buf->last += 1;

    ngx_memcpy(buf->last, b, 8);
    buf->last += 8;
}


static void
ngx_flv_metadata_write_keyframes_array(ngx_http_flv_file_t *flv, ngx_buf_t *buf, ngx_array_t *array, ngx_str_t *name, off_t adjustment)
{
    ngx_uint_t        i, size;
    double           *node;

    size = flv->end_frame_index - flv->start_frame_index + 1;

    ngx_flv_set_16value(buf->last, name->len);
    buf->last += 2;

    ngx_memcpy(buf->last, name->data, name->len);
    buf->last += name->len;

    ngx_flv_set_8value(buf->last, NGX_HTTP_FLV_SCRIPT_TAG_STRICT_ARRAY_TYPE);
    buf->last += 1;

    ngx_flv_set_32value(buf->last, size);
    buf->last += 4;

    node = array->elts;
    for (i = flv->start_frame_index; i <= flv->end_frame_index; i++) {
        ngx_flv_metadata_write_double(buf, node[i] + adjustment);
    }
}


static void
ngx_flv_metadata_write_array_end(ngx_buf_t *buf)
{
    ngx_flv_set_16value(buf->last, 0);
    buf->last += 2;

    ngx_flv_set_8value(buf->last, NGX_HTTP_FLV_SCRIPT_TAG_OBJECT_END_TYPE);
    buf->last += 1;
}


static ngx_int_t
ngx_http_flv_package_metadata(ngx_http_flv_file_t *flv)
{
    off_t               adjustment;
    ngx_uint_t          size, origin_header_length, compute_header_length;
    ngx_str_t           filepositions_name = ngx_string("filepositions");
    ngx_str_t           times_name = ngx_string("times");
    ngx_buf_t           buf;

    /* FLV Header + Previous Tag Size*/
    compute_header_length = NGX_HTTP_FLV_HEADER_SIZE + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE;

    /* MetaData Tag Header*/
    buf.pos = ngx_pcalloc(flv->request->pool, flv->metadata_tag_size);
    if (buf.pos == NULL) {
        return NGX_ERROR;
    }
    buf.last = buf.pos;
    buf.memory = 1;

    size = NGX_HTTP_FLV_TAG_HEADER_SIZE;
    ngx_memcpy(buf.last, flv->metadata_tag_buf.pos, size);
    buf.last += size;
    compute_header_length += size;

    /* AMF Packet + ECM array*/
    size = NGX_HTTP_FLV_SCRIPT_FIRST_AMF_HEADER_SIZE + NGX_HTTP_FLV_SCRIPT_SECOND_AMF_HEADER_SIZE;
    ngx_memcpy(buf.last, flv->buffer_metadata_start, size);
    buf.last += size;
    ngx_flv_set_32value(buf.last - 4, 2);
    compute_header_length += size;

    /* Duration */
    ngx_str_t duration_name = ngx_string("duration");
    ngx_flv_set_16value(buf.last, duration_name.len);
    buf.last += 2;
    compute_header_length += 2;

    ngx_memcpy(buf.last, duration_name.data, duration_name.len);
    buf.last += duration_name.len;
    compute_header_length += duration_name.len;

    ngx_flv_metadata_write_double(&buf, flv->duration);
    compute_header_length += 9;

    /* keyframes array key */
    size = 9;
    ngx_flv_set_16value(buf.last, size);
    buf.last += 2;
    compute_header_length += 2;

    ngx_memcpy(buf.last, "keyframes", size);
    buf.last += size;
    compute_header_length += size;

    ngx_flv_set_8value(buf.last, NGX_HTTP_FLV_SCRIPT_TAG_OBJECT_TYPE);
    buf.last += 1;
    compute_header_length += 1;

    /* keyframes strict array value */
    compute_header_length += (flv->end_frame_index - flv->start_frame_index + 1) * 9 * 2
                             + 7 * 2 + filepositions_name.len + times_name.len;

    /* keyframes array end */
    compute_header_length += 3;

    /* ECM array end */
    compute_header_length += 3;

    /* Metadata previous header */
    compute_header_length += 4;

    /* H.264 special config tag */
    if (flv->video_format == NGX_HTTP_FLV_VIDEO_AVC_TYPE) {
        origin_header_length = flv->offset;
        compute_header_length += flv->video_tag_size + flv->audio_tag_size;
    } else {
        origin_header_length = flv->offset - flv->video_tag_size - flv->audio_tag_size;
    }

    adjustment = compute_header_length - origin_header_length;

    /* keyframes strict array data*/
    ngx_flv_metadata_write_keyframes_array(flv, &buf, flv->metadata_filepositions, &filepositions_name, adjustment);
    ngx_flv_metadata_write_keyframes_array(flv, &buf, flv->metadata_times, &times_name, 0);

    /* keyframes array end + ECM array end*/
    ngx_flv_metadata_write_array_end(&buf);
    ngx_flv_metadata_write_array_end(&buf);

    /* Previous Header Size */
    size = buf.last - buf.pos;
    ngx_flv_set_32value(buf.last, size);
    buf.last += 4;

    /* Modify The Data Size*/
    size -= NGX_HTTP_FLV_TAG_HEADER_SIZE;
    ngx_flv_set_24value(buf.pos + 1, size);

    flv->metadata_tag_buf.pos = buf.pos;
    flv->metadata_tag_buf.last = buf.last;

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_buf_read_tag(ngx_http_flv_file_t *flv)
{
    ngx_int_t                rc;
    uint8_t                  tag_type;
    uint32_t                 tag_data_size;
    ngx_flv_tag_header_t    *tag_header;
    ngx_http_request_t      *r;

    r = flv->request;

    while (flv->buffer_pos < flv->buffer_end) {

        if (ngx_http_flv_buf_read(flv, NGX_HTTP_FLV_TAG_HEADER_SIZE) != NGX_OK) {
            return NGX_ERROR;
        }

        tag_header = (ngx_flv_tag_header_t *)flv->buffer_pos;
        tag_type = ngx_flv_get_8value(&tag_header->type);
        tag_data_size = ngx_flv_get_24value(tag_header->datasize);

        ngx_flv_tag_next(flv, NGX_HTTP_FLV_TAG_HEADER_SIZE);

        if (flv->buffer_pos + (off_t) tag_data_size + NGX_HTTP_FLV_PREVIOUS_TAG_SIZE > flv->buffer_end) {
            if ((flv->video_parsed == 0) || (flv->audio_parsed == 0)) {

                 ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                          "ngx_http_flv_buf_read_tag: tag too large %uL, need larger buffer",
                          tag_data_size);

                 r->headers_out.content_type.data = ngx_pnalloc(r->pool, 128);
                 if (r->headers_out.content_type.data == NULL) {
                     return NGX_ERROR;
                 }

                 r->headers_out.content_type_len = ngx_sprintf(r->headers_out.content_type.data, "%O", flv->offset + tag_data_size + 1024) - r->headers_out.content_type.data;
                 r->headers_out.content_type.len = r->headers_out.content_type_len;

                 return NGX_HTTP_NOT_IMPLEMENTED;
            }

            return NGX_OK;
        }

        switch (tag_type) {
            case NGX_HTTP_FLV_SCRIPT_TYPT:
                rc = ngx_http_flv_parse_metadata_tag(flv, tag_data_size);
                break;

            case NGX_HTTP_FLV_VIDEO_TYPT:
                rc = ngx_http_flv_parse_video_tag(flv, tag_data_size);
                break;

            case NGX_HTTP_FLV_AUDIO_TYPT:
                rc = ngx_http_flv_parse_audio_tag(flv, tag_data_size);
                break;

            default:
               ngx_log_error(NGX_LOG_ERR, flv->log, 0,
                          "ngx_http_flv_buf_read_tag: bad tag type %d",
                          tag_type);
               return NGX_ERROR;
        }

        if (rc != NGX_OK) {
            return rc;
        }

        if (flv->video_parsed && flv->audio_parsed) {

            if (flv->metadata_parsed) {
                return ngx_http_flv_package_metadata(flv);
            }

            return NGX_OK;
        }
    }

    return NGX_OK;
}


static void
ngx_http_flv_set_tag_timestamp(ngx_http_flv_file_t *flv, ngx_buf_t *tag, double start_timestamp)
{
    u_char     *header;
    uint32_t   timestamp;

    timestamp = start_timestamp * 1000;
    header = tag->pos + NGX_HTTP_FLV_TAG_HEADER_TIMESTAMP_OFFSET;

    ngx_flv_set_timestamp(header, timestamp);
}


static void
ngx_http_flv_process_body(ngx_http_request_t *r)
{
    ngx_int_t                  rc, start, end;
    ngx_str_t                  value;
    ngx_buf_t                 *tag, *buf;
    ngx_chain_t              **prev;
    ngx_http_flv_file_t        flv;

    start = 0;
    end = -1;
    if (r->args.len) {

        if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {

            start = ngx_atoof(value.data, value.len);

            if (start == NGX_ERROR) {
                start = 0;
            }
        }

        if (ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK) {

            end = ngx_atoof(value.data, value.len);

            if (end == NGX_ERROR) {
                end = -1;
            }
        }
    }

    if ((end != -1) && (end < start)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_flv_process_body: bad start or end args");

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    buf = ngx_http_flv_read_body(r);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_flv_process_body: body is NULL or too large");

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    ngx_memzero(&flv, sizeof(ngx_http_flv_file_t));
    flv.log = r->connection->log;
    flv.start = (ngx_uint_t)start;
    flv.end = end;
    flv.start_offset = -1;
    flv.end_offset = -1;
    flv.request = r;
    flv.buffer_start = buf->pos;
    flv.buffer_pos = buf->pos;
    flv.buffer_end = buf->end;

    rc = ngx_http_flv_validate_header(&flv);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_flv_process_body: validate header failed");

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    rc = ngx_http_flv_buf_read_tag(&flv);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_flv_process_body: read tag failed");

        if (rc == NGX_HTTP_NOT_IMPLEMENTED) {
            ngx_http_finalize_request(r, 299);
        } else {
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        }
        return;
    }

    /* header tag */
    tag = &flv.header_tag_buf;
    tag->memory = 1;
    tag->pos = ngx_flv_header;
    tag->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;

    flv.header_tag.next = NULL;
    flv.header_tag.buf = tag;

    /* tailer tag */
    tag = &flv.tailer_tag_buf;
    tag->last_buf = 1;

    flv.tailer_tag.next = NULL;
    flv.tailer_tag.buf = tag;

    /* output chain*/
    prev = &flv.out;

    *prev = &flv.header_tag;
    prev = &flv.header_tag.next;
    flv.content_length = sizeof(ngx_flv_header) - 1;

    if (flv.metadata_tag.buf) {
        ngx_http_flv_set_tag_timestamp(&flv, &flv.metadata_tag_buf, flv.start_timestamp);

        *prev = &flv.metadata_tag;
        prev = &flv.metadata_tag.next;
        flv.content_length += (flv.metadata_tag_buf.last - flv.metadata_tag_buf.pos);
    }

    if (flv.video_format == NGX_HTTP_FLV_VIDEO_AVC_TYPE) {
        if (flv.start_frame_index != 0) {
            ngx_http_flv_set_tag_timestamp(&flv, &flv.video_tag_buf, flv.start_timestamp);

            *prev = &flv.video_tag;
            prev = &flv.video_tag.next;
            flv.content_length += flv.video_tag_size;

            ngx_http_flv_set_tag_timestamp(&flv, &flv.audio_tag_buf, flv.start_timestamp);
            *prev = &flv.audio_tag;
            prev = &flv.audio_tag.next;
            flv.content_length += flv.audio_tag_size;
        }
    }

    *prev = &flv.tailer_tag;

    r->allow_ranges = 0;

    r->headers_out.content_type.data = ngx_pnalloc(r->pool, 128);
    if (r->headers_out.content_type.data == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (end != -1) {
        r->headers_out.content_type_len = ngx_sprintf(r->headers_out.content_type.data, "%O-%O", flv.start, flv.end - 1) - r->headers_out.content_type.data;
        r->headers_out.content_type.len = r->headers_out.content_type_len;
    } else {
        r->headers_out.content_type_len = ngx_sprintf(r->headers_out.content_type.data, "%O-", flv.start) - r->headers_out.content_type.data;
        r->headers_out.content_type.len = r->headers_out.content_type_len;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = flv.content_length;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_finalize_request(r, ngx_http_output_filter(r, flv.out));
}


static ngx_int_t
ngx_http_flv_compute_offset_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;

    if (r->method != NGX_HTTP_POST) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_flv_compute_offset_handler: need POST method");

        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_flv_process_body);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_flv_handler(ngx_http_request_t *r)
{
    u_char                    *last;
    off_t                      start, len;
    size_t                     root;
    ngx_int_t                  rc;
    ngx_uint_t                 level, i;
    ngx_str_t                  path, value;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out[2];
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

    start = 0;
    len = of.size;
    i = 1;

    if (r->args.len) {

        if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {

            start = ngx_atoof(value.data, value.len);

            if (start == NGX_ERROR || start >= len) {
                start = 0;
            }

            if (start) {
                len = sizeof(ngx_flv_header) - 1 + len - start;
                i = 0;
            }
        }
    }

    log->action = "sending flv to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (i == 0) {
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->pos = ngx_flv_header;
        b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
        b->memory = 1;

        out[0].buf = b;
        out[0].next = &out[1];
    }


    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = start;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out[1].buf = b;
    out[1].next = NULL;

    return ngx_http_output_filter(r, &out[i]);
}


static void *
ngx_http_flv_create_conf(ngx_conf_t *cf)
{
    ngx_http_flv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_flv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->max_buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_flv_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flv_conf_t *prev = parent;
    ngx_http_flv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->max_buffer_size, prev->max_buffer_size,
                              10 * 1024 * 1024);

    return NGX_CONF_OK;
}


static char *
ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_flv_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_flv_compute_offset(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_flv_compute_offset_handler;

    return NGX_CONF_OK;
}

