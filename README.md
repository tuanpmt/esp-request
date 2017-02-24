# Lightweight HTTP client for ESP32 
## Example 
```cpp
int upload_cb(request_t *req, char *buffer, int len)
{
    write(buffer, len);
    return len;
}
request *req = req_new("http://username:pass@host.com:port/api/get");
//or
//request *req = req_new("https://google.com"); //for SSL
req_setopt(req, REQ_SET_HEADER, "header=value");
req_setopt(req, REQ_SET_METHOD, "POST");
req_setopt(req, REQ_SET_POSTFIELD, "test=data&test2=data2");
status = req_perform(req);
req_cleanup(req);
```

## Todo  
- [x] Follow redirect
- [x] Support SSL
- [ ] Support Basic Auth
- [ ] Support set post field
- [ ] Support Upload multipart
- [ ] Support Cookie
