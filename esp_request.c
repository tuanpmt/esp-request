#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "esp_request.h"
#include "esp_log.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/igmp.h"

#define REQ_TAG "HTTP_REQ"

#define REQ_CHECK(check, log, ret) if(check) ESP_LOGE(REQ_TAG, log);ret;

static int resolve_dns(const char *host, struct sockaddr_in *ip) {
    struct hostent *he;
    struct in_addr **addr_list;
    he = gethostbyname(host);
    if(he == NULL)
        return 0;
    addr_list = (struct in_addr **)he->h_addr_list;
    if(addr_list[0] == NULL)
        return 0;
    ip->sin_family = AF_INET;
    memcpy(&ip->sin_addr, addr_list[0], sizeof(ip->sin_addr));
    return 1;
}

static char *http_auth_basic_encode(const char *username, const char *password)
{
    return NULL;
}


static int nossl_connect(request_t *req)
{
    int socket;
    struct sockaddr_in remote_ip;
    struct timeval tv;
    list_t *host, *port, *timeout;
    bzero(&remote_ip, sizeof(struct sockaddr_in));
    //if stream_host is not ip address, resolve it AF_INET,servername,&serveraddr.sin_addr
    host = list_get_key(req->opt, "host");
    if(host == NULL)
        return -1;
    if(inet_pton(AF_INET, (const char*)host->value, &remote_ip.sin_addr) != 1) {
        if(!resolve_dns((const char*)host->value, &remote_ip)) {
            return -1;
        }
    }
    socket = socket(PF_INET, SOCK_STREAM, 0);
    REQ_CHECK(socket < 0, "socket failed", return -1);

    port = list_get_key(req->opt, "port");
    if(port == NULL)
        return -1;

    remote_ip.sin_family = AF_INET;
    remote_ip.sin_port = htons(atoi(port->value));

    tv.tv_sec = 10; //default timeout is 10 seconds
    timeout = list_get_key(req->opt, "timeout");
    if(timeout) {
        tv.tv_sec = atoi(timeout->value);
    }
    tv.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET,SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(socket, (struct sockaddr * )(&remote_ip), sizeof(struct sockaddr)) != 0) {
        close(socket);
        return -1;
    }
    return socket;
}
static int ssl_connect(request_t *req)
{
    req->socket = nossl_connect(req);
    REQ_CHECK(req->socket < 0, "socket failed", return -1);

    //TODO: Check
    req->ctx = SSL_CTX_new(TLSv1_1_client_method());
    req->ssl = SSL_new(req->ctx);
    SSL_set_fd(req->ssl, req->socket);
    SSL_connect(req->ssl);
    return 0;
}
static int ssl_write(request_t *req, char *buffer, int len)
{
    return SSL_write(req->ssl, buffer, len);
}

static int nossl_write(request_t *req, char *buffer, int len)
{
    return write(req->socket, buffer, len);
}

static int ssl_read(request_t *req, char *buffer, int len)
{
    return SSL_read(req->ssl, buffer, len);
}

static int nossl_read(request_t *req, char *buffer, int len)
{
    return read(req->socket, buffer, len);
}
static int ssl_close(request_t *req)
{
    return 0;
}

static int nossl_close(request_t *req)
{
    return 0;
}
static int req_setopt_from_uri(request_t *req, const char* uri)
{
    parsed_uri_t *puri;
    char port[] = "443";

    puri = parse_uri(uri);

    if(puri == NULL) {
        return -1;
    }
    if(strcasecmp(puri->scheme, "https") == 0) {
        req_setopt(req, REQ_SET_SECURITY, "true");
    } else {
        req_setopt(req, REQ_SET_SECURITY, "false");
        strcpy(port, "80");
        port[2] = 0;
    }

    if(puri->username && puri->password) {
        char *auth = http_auth_basic_encode(puri->username, puri->password);
        if(auth) {
            req_setopt(req, REQ_SET_HEADER, auth);
            free(auth);
        }

    }

    req_setopt(req, REQ_SET_HOST, puri->host);
    req_setopt(req, REQ_SET_PATH, puri->path);
    //port
    if(puri->port) {
        req_setopt(req, REQ_SET_PORT, puri->port);
    } else {
        req_setopt(req, REQ_SET_PORT, port);
    }
    free_parsed_uri(puri);
    return 0;
}
request_t *req_new(const char *uri)
{
    request_t *req = calloc(1, sizeof(request_t));

    REQ_CHECK(req == NULL, "Error allocate req", return NULL);

    req->buffer = malloc(1024);
    //TODO: Free req before return
    REQ_CHECK(req->buffer == NULL, "Error allocate buffer", return NULL);

    req->opt = calloc(1, sizeof(list_t));
    req->header = calloc(1, sizeof(list_t));

    req_setopt_from_uri(req, uri);

    req_setopt(req, REQ_REDIRECT_FOLLOW, "true");
    req_setopt(req, REQ_SET_METHOD, "GET");
    req_setopt(req, REQ_SET_HEADER, "User-Agent: ESP32 Http Client");
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
            list_set_key(req->header, "Host", data);
            break;
        case REQ_SET_PORT:
            list_set_key(req->opt, "port", data);
            break;
        case REQ_SET_PATH:
            list_set_key(req->opt, "path", data);
            break;
        case REQ_SET_URI:
            req_setopt_from_uri(req, data);
            break;
        case REQ_SET_SECURITY:
            list_set_key(req->opt, "secure", data);
            if(list_check_key(req->opt, "secure", "true")) {
                req->_read = ssl_read;
                req->_write = ssl_write;
                req->_connect = ssl_connect;
                req->_close = ssl_close;
            } else {
                req->_read = nossl_read;
                req->_write = nossl_write;
                req->_connect = nossl_connect;
                req->_close = nossl_close;
            }

            break;
        case REQ_SET_POSTFIELDS:
        case REQ_FUNC_UPLOAD_DATA:
        case REQ_FUNC_DOWNLOAD_DATA:
            break;
        case REQ_REDIRECT_FOLLOW:
            list_set_key(req->opt, "follow", data);
            break;
        default:
            break;
    }
}
static int req_process_upload(request_t *req)
{
    int tx_write_len = 0;
    list_t *found;


    found = list_get_key(req->opt, "method");
    if(found)
        tx_write_len += sprintf(req->buffer + tx_write_len, "GET /%s HTTP/1.1\r\n", (char*)found->value);
    //TODO: Check header len < 1024
    found = req->header;
    while(found->next != NULL) {
        found = found->next;
        tx_write_len += sprintf(req->buffer + tx_write_len, "%s: %s\r\n", (char*)found->key, (char*)found->value);
    }
    tx_write_len += sprintf(req->buffer + tx_write_len, "\r\n");
    REQ_CHECK(req->_write(req, req->buffer, tx_write_len) < 0, "Error write header", return -1);

    if(req->upload_callback) {
        while((tx_write_len = req->upload_callback(req, (void *)req->buffer, 1024)) > 0) {
            REQ_CHECK(req->_write(req, req->buffer, tx_write_len) < 0, "Error write data", return -1);
        }
    }
    return 0;
}

static int req_process_download(request_t *req)
{
    int rx_len, process_idx = 0;
    // req->response = new_response();
    do {
        rx_len = req->_read(req, req->buffer, 1024);
        // process_data(req->buffer, rx_len);
    } while(rx_len > 0 );

    return 0;
}
int req_perform(request_t *req)
{
    int status_code = -1;

    do {
        REQ_CHECK(req->_connect(req) < 0, "Error connnect", break);
        REQ_CHECK((status_code = req_process_upload(req)) < 0, "Error send request", break);

        status_code = req_process_download(req);

        if((status_code == 301 || status_code == 302) && list_check_key(req->opt, "follow", "true")) {
            continue;
        } else {
            break;
        }
    } while(1);
    req->_close(req);
    return status_code;
}

void req_clean(request_t *req)
{
    list_clear(req->opt);
    list_clear(req->header);
    free(req);
}
