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
#include "req_list.h"

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
    req_list_t *host, *port, *timeout;
    bzero(&remote_ip, sizeof(struct sockaddr_in));
    //if stream_host is not ip address, resolve it AF_INET,servername,&serveraddr.sin_addr
    host = req_list_get_key(req->opt, "host");
    REQ_CHECK(host == NULL, "host = NULL", return -1);

    if(inet_pton(AF_INET, (const char*)host->value, &remote_ip.sin_addr) != 1) {
        if(resolve_dns((const char*)host->value, &remote_ip) < 0) {
            return -1;
        }
    }

    socket = socket(PF_INET, SOCK_STREAM, 0);
    REQ_CHECK(socket < 0, "socket failed", return -1);

    port = req_list_get_key(req->opt, "port");
    if(port == NULL)
        return -1;

    remote_ip.sin_family = AF_INET;
    remote_ip.sin_port = htons(atoi(port->value));

    tv.tv_sec = 10; //default timeout is 10 seconds
    timeout = req_list_get_key(req->opt, "timeout");
    if(timeout) {
        tv.tv_sec = atoi(timeout->value);
    }
    tv.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ESP_LOGD(REQ_TAG, "[sock=%d],connecting to server IP:%s,Port:%s...",
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

    req->opt = malloc(sizeof(req_list_t));
    memset(req->opt, 0, sizeof(req_list_t));
    req->header = malloc(sizeof(req_list_t));
    memset(req->header, 0, sizeof(req_list_t));

    req->response = malloc(sizeof(response_t));
    REQ_CHECK(req->response == NULL, "Error create response", return NULL);
    memset(req->response, 0, sizeof(response_t));

    req->response->header = malloc(sizeof(req_list_t));
    REQ_CHECK(req->response->header == NULL, "Error create response header", return NULL);
    memset(req->response->header, 0, sizeof(req_list_t));


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
    req_list_t *tmp;
    char *host_w_port = malloc(1024);
    if(!req || !data)
        return;
    switch(opt) {
        case REQ_SET_METHOD:
            req_list_set_key(req->opt, "method", data);
            break;
        case REQ_SET_HEADER:
            req_list_set_from_string(req->header, data);
            break;
        case REQ_SET_HOST:
            req_list_set_key(req->opt, "host", data);
            tmp = req_list_get_key(req->opt, "port");
            if(tmp != NULL) {
                sprintf(host_w_port, "%s:%s", (char*)data, (char*)tmp->value);
            } else {
                sprintf(host_w_port, "%s", (char*)data);
            }
            req_list_set_key(req->header, "Host", host_w_port);
            break;
        case REQ_SET_PORT:
            req_list_set_key(req->opt, "port", data);
            tmp = req_list_get_key(req->opt, "host");
            if(tmp != NULL) {
                sprintf(host_w_port, "%s:%s", (char*)tmp->value, (char*)data);
                req_list_set_key(req->header, "Host", host_w_port);
            }

            break;
        case REQ_SET_PATH:
            req_list_set_key(req->opt, "path", data);
            break;
        case REQ_SET_URI:
            req_setopt_from_uri(req, data);
            break;
        case REQ_SET_SECURITY:
            req_list_set_key(req->opt, "secure", data);
            if(req_list_check_key(req->opt, "secure", "true")) {
                ESP_LOGD(REQ_TAG, "Secure");
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
            req_list_set_key(req->header, "Content-Type", "application/x-www-form-urlencoded");
            req_list_set_key(req->opt, "method", "POST");
        case REQ_SET_DATAFIELDS:
            post_len = strlen((char*)data);
            sprintf(len_str, "%d", post_len);
            req_list_set_key(req->opt, "postfield", data);
            req_list_set_key(req->header, "Content-Length", len_str);
            break;
        case REQ_FUNC_UPLOAD_CB:
            req->upload_callback = data;
            break;
        case REQ_FUNC_DOWNLOAD_CB:
            req->download_callback = data;
            break;
        case REQ_REDIRECT_FOLLOW:
            req_list_set_key(req->opt, "follow", data);
            break;
        default:
            break;
    }
    free(host_w_port);
}
static int req_process_upload(request_t *req)
{
    int tx_write_len = 0;
    req_list_t *found;


    found = req_list_get_key(req->opt, "method");
    REQ_CHECK(found == NULL, "method required", return -1);
    tx_write_len += sprintf(req->buffer->data + tx_write_len, "%s ", (char*)found->value);

    found = req_list_get_key(req->opt, "path");
    REQ_CHECK(found == NULL, "path required", return -1);
    tx_write_len += sprintf(req->buffer->data + tx_write_len, "%s HTTP/1.1\r\n", (char*)found->value);

    //TODO: Check header len < REQ_BUFFER_LEN
    found = req->header;
    while(found->next != NULL) {
        found = found->next;
        tx_write_len += sprintf(req->buffer->data + tx_write_len, "%s: %s\r\n", (char*)found->key, (char*)found->value);
    }
    tx_write_len += sprintf(req->buffer->data + tx_write_len, "\r\n");

    // ESP_LOGD(REQ_TAG, "Request header, len= %d, real_len= %d\r\n%s", tx_write_len, strlen(req->buffer->data), req->buffer->data);

    REQ_CHECK(req->_write(req, req->buffer->data, tx_write_len) < 0, "Error write header", return -1);

    found = req_list_get_key(req->opt, "postfield");
    if(found) {
        ESP_LOGD(REQ_TAG, "Begin write %d bytes", strlen((char*)found->value));
        int bwrite = req->_write(req, (char*)found->value, strlen((char*)found->value));
        ESP_LOGD(REQ_TAG, "end write %d bytes", bwrite);
        if(bwrite < 0) {
            ESP_LOGE(REQ_TAG, "Error write");
            return -1;
        }
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
    req->buffer->bytes_total = 0;
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
        ESP_LOGD(REQ_TAG, "move=%d, write=%d, read=%d", bytes_inside_buffer, req->buffer->bytes_write, req->buffer->bytes_read);
    }
    if(!req->buffer->at_eof)
    {
        //reset if buffer full
        if(req->buffer->bytes_write == req->buffer->bytes_read) {
            req->buffer->bytes_write = 0;
            req->buffer->bytes_read = 0;
        }
        buffer_free_bytes = REQ_BUFFER_LEN - req->buffer->bytes_write;
        ESP_LOGD(REQ_TAG, "Begin read %d bytes", buffer_free_bytes);
        bread = req->_read(req, (void*)(req->buffer->data + req->buffer->bytes_write), buffer_free_bytes);
        // ESP_LOGD(REQ_TAG, "bread = %d, bytes_write = %d, buffer_free_bytes = %d", bread, req->buffer->bytes_write, buffer_free_bytes);
        ESP_LOGD(REQ_TAG, "End read, byte read= %d bytes", bread);
        if(bread < 0) {
            req->buffer->at_eof = 1;
            return -1;
        }
        req->buffer->bytes_write += bread;
        req->buffer->data[req->buffer->bytes_write] = 0;//terminal string

        if(bread == 0) {
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
    int process_header = 1, header_off = 0;
    char *line;
    req_list_t *content_len;
    req->response->status_code = -1;
    reset_buffer(req);
    req_list_clear(req->response->header);
    req->response->len = 0;
    do {
        fill_buffer(req);
        if(process_header) {
            while((line = req_readline(req)) != NULL) {
                if(line[0] == 0) {
                    ESP_LOGD(REQ_TAG, "end process_idx=%d", req->buffer->bytes_read);
                    header_off = req->buffer->bytes_read;
                    process_header = 0; //end of http header
                    break;
                } else {
                    if(req->response->status_code < 0) {
                        char *temp = strstr(line, "HTTP/1.");
                        if(temp) {
                            char statusCode[4] = { 0 };
                            memcpy(statusCode, temp + 9, 3);
                            req->response->status_code = atoi(statusCode);
                            ESP_LOGD(REQ_TAG, "status code: %d", req->response->status_code);
                        }
                    } else {
                        req_list_set_from_string(req->response->header, line);
                        ESP_LOGD(REQ_TAG, "header line: %s", line);
                    }
                }
            }
        }

        if(process_header == 0)
        {
            if(req->buffer->at_eof) {
                fill_buffer(req);
            }

            req->buffer->bytes_read = req->buffer->bytes_write;
            content_len = req_list_get_key(req->response->header, "Content-Length");
            if(content_len) {
                req->response->len = atoi(content_len->value);
            }
            if(req->response->len && req->download_callback && (req->buffer->bytes_write - header_off) != 0) {
                if(req->download_callback(req, (void *)(req->buffer->data + header_off), req->buffer->bytes_write - header_off) < 0) break;

                req->buffer->bytes_total += req->buffer->bytes_write - header_off;
                if(req->buffer->bytes_total == req->response->len) {
                    break;
                }
            }
            header_off = 0;
            if(req->response->len == 0) {
                break;
            }

        }

    } while(req->buffer->at_eof == 0);
    return 0;
}

int req_perform(request_t *req)
{
    do {
        REQ_CHECK(req->_connect(req) < 0, "Error connnect", break);
        REQ_CHECK(req_process_upload(req) < 0, "Error send request", break);
        REQ_CHECK(req_process_download(req) < 0, "Error download", break);

        if((req->response->status_code == 301 || req->response->status_code == 302) && req_list_check_key(req->opt, "follow", "true")) {
            req_list_t *found = req_list_get_key(req->response->header, "Location");
            if(found) {
                req_list_set_key(req->header, "Referer", (const char*)found->value);
                req_setopt_from_uri(req, (const char*)found->value);
                ESP_LOGD(REQ_TAG, "Following: %s", (char*)found->value);
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
    req_list_clear(req->opt);
    req_list_clear(req->header);
    req_list_clear(req->response->header);
    free(req->opt);
    free(req->header);
    free(req->response->header);
    free(req->response);
    free(req->buffer->data);
    free(req->buffer);
    free(req);
}
