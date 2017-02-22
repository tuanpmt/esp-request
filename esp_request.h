#ifndef _ESP_REQUEST_H_
#define _ESP_REQUEST_H_
#include "list.h"
#include "uri_parser.h"
#include "openssl/ssl.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

typedef enum {
	REQ_SET_METHOD = 0x01,
	REQ_SET_HEADER,
	REQ_SET_HOST,
	REQ_SET_PORT,
	REQ_SET_PATH,
	REQ_SET_URI,
	REQ_SET_SECURITY,
	REQ_SET_POSTFIELDS,
	REQ_FUNC_DATACB,
	REQ_FUNC_HEADERCB,
	REQ_REDIRECT_FOLLOW
} REQ_OPTS;

typedef struct {
	list_t *opt;
	list_t *header;
	SSL_CTX *ctx;
    SSL *ssl;
    int socket;
    int (*connect)(void *req);
    int (*write)(void *req, void *data, int len);
    int (*read)(void *req, void *data, int len);
} request_t;

typedef struct {
	request_t *req;
} response_t;

typedef void (data_cb)(response_t *res, void *buffer, int len);
typedef void (header_cb)(response_t *res, list_t *header);

request_t *req_init(const char *url);
void req_setopt(request_t *req, REQ_OPTS opt, void* data);
void req_clean(request_t *req);
int req_perform(request_t *req);

#endif