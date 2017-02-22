# Simple HTTP client for ESP32 

```
request *req = req_new("http://url:port/path/to.ext");
req_setopt(req, REQ_HEADER, "header=value");
req_setopt(req, REQ_METHOD, "POST");
req_setopt(req, REQ_DATA_FUNCTION, "POST");
status = req_perform(req);
req_cleanup(req);
```
