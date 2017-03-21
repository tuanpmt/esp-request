/*
* @2017
* Tuan PM <tuanpm at live dot com>
*/

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "esp_request.h"
#include "esp_log.h"
#include "esp_system.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/igmp.h"

#define REQ_TAG "HTTP_REQ"

#define REQ_CHECK(check, log, ret) if(check) {ESP_LOGE(REQ_TAG, log);ret;}

static int resolve_dns(const char *host, struct sockaddr_in *ip) {
    struct hostent *he;
    struct in_addr **addr_list;
    he = gethostbyname(host);
    if(he == NULL)
        return -1;
    addr_list = (struct in_addr **)he->h_addr_list;
    if(addr_list[0] == NULL)
        return -1;
    ip->sin_family = AF_INET;
    memcpy(&ip->sin_addr, addr_list[0], sizeof(ip->sin_addr));
    return 0;
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
    REQ_CHECK(host == NULL, "host = NULL", return -1);

    if(inet_pton(AF_INET, (const char*)host->value, &remote_ip.sin_addr) != 1) {
        if(resolve_dns((const char*)host->value, &remote_ip) < 0) {
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
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ESP_LOGI(REQ_TAG, "[sock=%d],connecting to server IP:%s,Port:%s...",
             socket, ipaddr_ntoa((const ip_addr_t*)&remote_ip.sin_addr.s_addr), (char*)port->value);
    if(connect(socket, (struct sockaddr *)(&remote_ip), sizeof(struct sockaddr)) != 0) {
        close(socket);
        return -1;
    }
    req->socket = socket;
    return socket;
}
static int ssl_connect(request_t *req)
{
    nossl_connect(req);
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
    SSL_shutdown(req->ssl);
    SSL_free(req->ssl);
    close(req->socket);
    SSL_CTX_free(req->ctx);
    return 0;
}

static int nossl_close(request_t *req)
{
    return close(req->socket);
}
static int req_setopt_from_uri(request_t *req, const char* uri)
{
    //TODO: relative path
    parsed_uri_t *puri;
    char port[] = "443";
    puri = parse_uri(uri);
    REQ_CHECK(puri == NULL, "Error parse uri", return -1);

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
    request_t *req = malloc(sizeof(request_t));

    REQ_CHECK(req == NULL, "Error allocate req", return NULL);
    memset(req, 0, sizeof(request_t));

    req->buffer = malloc(sizeof(req_buffer_t));
    REQ_CHECK(req->buffer == NULL, "Error allocate buffer", return NULL);
    memset(req->buffer, 0, sizeof(req_buffer_t));

    req->buffer->data = malloc(REQ_BUFFER_LEN + 1); //1 byte null for end of string
    //TODO: Free req before return
    REQ_CHECK(req->buffer->data == NULL, "Error allocate buffer", return NULL);

    req->opt = malloc(sizeof(list_t));
    memset(req->opt, 0, sizeof(list_t));
    req->header = malloc(sizeof(list_t));
    memset(req->header, 0, sizeof(list_t));

    req->response = malloc(sizeof(response_t));
    REQ_CHECK(req->response == NULL, "Error create response", return NULL);
    memset(req->response, 0, sizeof(response_t));

    req->response->header = malloc(sizeof(list_t));
    REQ_CHECK(req->response->header == NULL, "Error create response header", return NULL);
    memset(req->response->header, 0, sizeof(list_t));


    req_setopt_from_uri(req, uri);

    req_setopt(req, REQ_REDIRECT_FOLLOW, "true");
    req_setopt(req, REQ_SET_METHOD, "GET");
    req_setopt(req, REQ_SET_HEADER, "User-Agent: ESP32 Http Client");
    return req;

}

void req_setopt(request_t *req, REQ_OPTS opt, void* data)
{
    int post_len;
    char len_str[10] = {0};
    if(!req || !data)
        return;
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
                ESP_LOGI(REQ_TAG, "Secure");
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
            list_set_key(req->header, "Content-Type", "application/x-www-form-urlencoded");
            list_set_key(req->opt, "method", "POST");
        case REQ_SET_DATAFIELDS:
            post_len = strlen((char*)data);
            sprintf(len_str, "%d", post_len);
            list_set_key(req->opt, "postfield", data);
            list_set_key(req->header, "Content-Length", len_str);
            break;
        case REQ_FUNC_UPLOAD_CB:
            req->upload_callback = data;
            break;
        case REQ_FUNC_DOWNLOAD_CB:
            req->download_callback = data;
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
    REQ_CHECK(found == NULL, "method required", return -1);
    tx_write_len += sprintf(req->buffer->data + tx_write_len, "%s ", (char*)found->value);

    found = list_get_key(req->opt, "path");
    REQ_CHECK(found == NULL, "path required", return -1);
    tx_write_len += sprintf(req->buffer->data + tx_write_len, "/%s HTTP/1.1\r\n", (char*)found->value);

    //TODO: Check header len < REQ_BUFFER_LEN
    found = req->header;
    while(found->next != NULL) {
        found = found->next;
        tx_write_len += sprintf(req->buffer->data + tx_write_len, "%s: %s\r\n", (char*)found->key, (char*)found->value);
    }
    tx_write_len += sprintf(req->buffer->data + tx_write_len, "\r\n");
    REQ_CHECK(req->_write(req, req->buffer->data, tx_write_len) < 0, "Error write header", return -1);

    found = list_get_key(req->opt, "postfield");
    if(found) {
        ESP_LOGI(REQ_TAG, "Write data len=%d", strlen((char*)found->value));
        REQ_CHECK(req->_write(req, (char*)found->value, strlen((char*)found->value)) < 0, "Error write post field", return -1);
    }

    if(req->upload_callback) {
        while((tx_write_len = req->upload_callback(req, (void *)req->buffer->data, REQ_BUFFER_LEN)) > 0) {
            REQ_CHECK(req->_write(req, req->buffer->data, tx_write_len) < 0, "Error write data", return -1);
        }
    }
    return 0;
}

static int reset_buffer(request_t *req)
{
    req->buffer->bytes_read = 0;
    req->buffer->bytes_write = 0;
    req->buffer->at_eof = 0;
    return 0;
}

static int fill_buffer(request_t *req)
{
    int bread;
    int bytes_inside_buffer = req->buffer->bytes_write - req->buffer->bytes_read;
    int buffer_free_bytes;
    if(bytes_inside_buffer)
    {
        memmove((void*)req->buffer->data, (void*)(req->buffer->data + req->buffer->bytes_read),
                bytes_inside_buffer);
        req->buffer->bytes_read = 0;
        req->buffer->bytes_write = bytes_inside_buffer;
        if(req->buffer->bytes_write < 0)
            req->buffer->bytes_write = 0;
        // ESP_LOGI(REQ_TAG, "move=%d, write=%d, read=%d", bytes_inside_buffer, req->buffer->bytes_write, req->buffer->bytes_read);
    }
    if(!req->buffer->at_eof)
    {
        //reset if buffer full
        if(req->buffer->bytes_write == req->buffer->bytes_read) {
            req->buffer->bytes_write = 0;
            req->buffer->bytes_read = 0;
        }
        buffer_free_bytes = REQ_BUFFER_LEN - req->buffer->bytes_write;
        bread = req->_read(req, (void*)(req->buffer->data + req->buffer->bytes_write), buffer_free_bytes);
        if(bread <= 0) {
            req->buffer->at_eof = 1;
            return -1;
        }
        req->buffer->bytes_write += bread;
        req->buffer->data[req->buffer->bytes_write] = 0;//terminal string

        if(bread != buffer_free_bytes) {
            req->buffer->at_eof = 1;
        }
    }

    return 0;
}


static char *req_readline(request_t *req)
{
    char *cr, *ret = NULL;
    if(req->buffer->bytes_read + 2 > req->buffer->bytes_write) {
        return NULL;
    }
    cr = strstr(req->buffer->data + req->buffer->bytes_read, "\r\n");
    if(cr == NULL) {
        return NULL;
    }
    memset(cr, 0, 2);
    ret = req->buffer->data + req->buffer->bytes_read;
    req->buffer->bytes_read += (cr - (req->buffer->data + req->buffer->bytes_read)) + 2;
    // ESP_LOGD(REQ_TAG, "next offset=%d", req->buffer->bytes_read);
    return ret;
}
static int req_process_download(request_t *req)
{
    int process_header = 1, data_len = 0;
    char *line;
    req->response->status_code = -1;
    reset_buffer(req);
    list_clear(req->response->header);
    do {
        fill_buffer(req);
        if(process_header) {
            while((line = req_readline(req)) != NULL) {
                if(line[0] == 0) {
                    // ESP_LOGI(REQ_TAG, "end process_idx=%d", req->buffer->bytes_read);
                    process_header = 0; //end of http header
                    break;
                } else {
                    if(req->response->status_code < 0) {
                        char *temp = strstr(line, "HTTP/1.");
                        if(temp) {
                            char statusCode[4] = { 0 };
                            memcpy(statusCode, temp + 9, 3);
                            req->response->status_code = atoi(statusCode);
                        }
                    } else {
                        list_set_from_string(req->response->header, line);
                    }
                }
            }
        }

        if(process_header == 0)
        {
            if(req->buffer->at_eof) {
                fill_buffer(req);
            }
            data_len += req->buffer->bytes_write;
            req->buffer->bytes_read = req->buffer->bytes_write;
            if(req->download_callback) {
                req->download_callback(req, (void *)req->buffer->data, req->buffer->bytes_write);
            }
        }

    } while(req->buffer->at_eof == 0);

    ESP_LOGI(REQ_TAG, "datalen=%d, freeme=%d", data_len, esp_get_free_heap_size());
    return 0;
}

int req_perform(request_t *req)
{
    do {
        REQ_CHECK(req->_connect(req) < 0, "Error connnect", break);
        REQ_CHECK(req_process_upload(req) < 0, "Error send request", break);
        REQ_CHECK(req_process_download(req) < 0, "Error download", break);

        if((req->response->status_code == 301 || req->response->status_code == 302) && list_check_key(req->opt, "follow", "true")) {
            list_t *found = list_get_key(req->response->header, "Location");
            if(found) {
                list_set_key(req->header, "Referer", (const char*)found->value);
                req_setopt_from_uri(req, (const char*)found->value);
                ESP_LOGI(REQ_TAG, "Following: %s", (char*)found->value);
                req->_close(req);
                continue;
            }
            break;
        } else {
            break;
        }
    } while(1);
    req->_close(req);
    return req->response->status_code;
}

void req_clean(request_t *req)
{
    list_clear(req->opt);
    list_clear(req->header);
    list_clear(req->response->header);
    free(req->opt);
    free(req->header);
    free(req->response->header);
    free(req->response);
    free(req->buffer->data);
    free(req->buffer);
    free(req);
}
