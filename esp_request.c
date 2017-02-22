#include <stdlib.h>
#include <string.h>
#include "esp_request.h"

static int ssl_connect(request_t *req)
{

}

static int nossl_connect(request_t *req)
{

}

static int ssl_write(request_t *req, void *data, int len)
{

}

static int nossl_write(request_t *req, void *data, int len)
{

}

static int ssl_read(request_t *req, void *data, int len)
{

}

static int nossl_read(request_t *req, void *data, int len)
{
	
}
request_t *req_init(request_t * req, const char *uri)
{
	parsed_uri_t *puri;
	int secure = 0, redirect = 1, port = 80;
	request_t *req = calloc(1, sizeof(request_t));
	
	if(req == NULL)
		return NULL;

	puri = parse_uri(uri);

	if(puri == NULL) {
		free(req);
		return NULL;
	}
	if(strcasecmp(puri->scheme, "https") == 0) {
		secure = 1;
	}
	
	//port 
	if(puri->port) {
		port = atoi(puri->port);
	}

	if (puri->username && puri->password) {
		// char *auth = http_auth_basic_encode(puri->username, puri->password);
		// req_setopt(req, REQ_SET_HEADER, auth);
	}	

	req_setopt(req, REQ_SET_HOST, puri->host);
	req_setopt(req, REQ_SET_PATH, puri->path);
	req_setopt(req, REQ_SET_PORT, &port);
	req_setopt(req, REQ_SET_SECURITY, &secure);
	req_setopt(req, REQ_REDIRECT_FOLLOW, &redirect);
	req_setopt(req, REQ_SET_METHOD, "GET");
	req_setopt(req, REQ_SET_HEADER, "User-Agent: ESP32 Http Client");
	req_setopt(req, REQ_SET_HEADER, "Proxy-Connection: Keep-Alive");
	req_setopt(req, REQ_SET_HEADER, "Proxy-Connection: Keep-Alive");
	return req;
}

void req_setopt(request_t *req, REQ_OPTS opt, void* data)
{
	switch(opt) {
		case REQ_SET_METHOD:
			list_set_key(req->opt, "method", data);
			break;
		case REQ_SET_HEADER:
			list_set_from_string(req->header, data);
			break;
		case REQ_SET_HOST:
			list_set_key(req->opt, "host", data);
			break;
		case REQ_SET_PORT:
			list_set_key(req->opt, "port", data);
			break;
		case REQ_SET_PATH:
			list_set_key(req->opt, "path", data);
			break;
		case REQ_SET_URI:
			break;
		case REQ_SET_SECURITY:
			int *secure = data;
			if(*secure) {
				req->read = ssl_read;
				req->write = ssl_write;
				req->connect = ssl_connect;
			} else {
				req->read = nossl_read;
				req->write = nossl_write;
				req->connect = nossl_connect;
			}
			list_set_key(req->opt, "secure", data);
			break;
		case REQ_SET_POSTFIELDS:
		case REQ_FUNC_DATACB:
		case REQ_FUNC_HEADERCB:
		case REQ_REDIRECT_FOLLOW:
		default:
			break;
	}
}
int req_perform(request_t *req)
{
	//lock req
	//create req copy
	//unlock req
	//create thread with req copy/free after finish
	return 0;
}

void req_clean(request_t *req)
{
	list_clear(req->opt);
	list_clear(req->header);
	free(req);
}