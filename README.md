# Simple and Powerful HTTP client for ESP32 

```cpp
int upload_cb(request_t *req, char *buffer, int len)
{
    write(buffer, len);
    return len;
}
request *req = req_new("http://username:pass@host.com:port/api/get");
req_setopt(req, REQ_SET_HEADER, "header=value");
req_setopt(req, REQ_SET_METHOD, "POST");
req_setopt(req, REQ_SET_POSTFIELD, "test=data&test2=data2");
status = req_perform(req);
req_cleanup(req);
```

# Todo 
- [ ] Support SSL
- [ ] Follow redirect
- [ ] Support Basic Auth
- [ ] Support set post field
- [ ] Support Upload multipart
- [ ] Support Cookie
