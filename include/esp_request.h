#ifndef _ESP_REQUEST_H_
#define _ESP_REQUEST_H_
#include "req_list.h"
#include "uri_parser.h"
#include "openssl/ssl.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

#define REQ_BUFFER_LEN  (2048)
typedef enum {
    REQ_SET_METHOD = 0x01,
    REQ_SET_HEADER,
    REQ_SET_HOST,
    REQ_SET_PORT,
    REQ_SET_PATH,
    REQ_SET_URI,
    REQ_SET_SECURITY,
    REQ_SET_POSTFIELDS,
    REQ_SET_DATAFIELDS,
    REQ_SET_UPLOAD_LEN,
    REQ_FUNC_DOWNLOAD_CB,
    REQ_FUNC_UPLOAD_CB,
    REQ_REDIRECT_FOLLOW
} REQ_OPTS;



typedef struct response_t {
    req_list_t *header;
    int status_code;
} response_t;

typedef struct {
    int bytes_read;
    int bytes_write;
    char *data;
    int at_eof;
} req_buffer_t;

typedef struct request_t {
    req_list_t *opt;
    req_list_t *header;
    SSL_CTX *ctx;
    SSL *ssl;
    req_buffer_t *buffer;
    int socket;
    int (*_connect)(struct request_t *req);
    int (*_read)(struct request_t *req, char *buffer, int len);
    int (*_write)(struct request_t *req, char *buffer, int len);
    int (*_close)(struct request_t *req);
    int (*upload_callback)(struct request_t *req, void *buffer, int len);
    int (*download_callback)(struct request_t *req, void *buffer, int len);
    response_t *response;
} request_t;

typedef int (*download_cb)(request_t *req, void *buffer, int len);
typedef int (*upload_cb)(request_t *req, void *buffer, int len);


request_t *req_new(const char *url);
void req_setopt(request_t *req, REQ_OPTS opt, void* data);
void req_clean(request_t *req);
int req_perform(request_t *req);

#endif
