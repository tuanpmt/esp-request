# Lightweight HTTP client for ESP32 
## Example 
```cpp
request *req = req_new("http://uri.com/path/to/file.txt");
//or
//request *req = req_new("https://google.com"); //for SSL
req_setopt(req REQ_SET_HEADER, "header=value");
req_setopt(req, REQ_SET_METHOD, "POST");
req_setopt(req, REQ_SET_POSTFIELD, "test=data&test2=data2");
status = req_perform(req);
printf("HTTP response status code = %d\r\n", status);
req_cleanup(req);
```

## Usage 
- Create ESP-IDF application https://github.com/espressif/esp-idf-template
- Clone `git submodule add https://github.com/tuanpmt/esp-request components/esp-request`
- Example esp-request application: https://github.com/tuanpmt/esp-request-app

## API 

### Function
- `req_new`
- `req_setopt`
- `req_clean`

### Options for `req_setopt`  
- REQ_SET_METHOD
- REQ_SET_HEADER
- REQ_SET_HOST
- REQ_SET_PORT 
- REQ_SET_PATH
- REQ_SET_URI
- REQ_SET_SECURITY
- REQ_SET_POSTFIELDS
- REQ_SET_UPLOAD_LEN
- REQ_FUNC_DOWNLOAD_DATA
- REQ_FUNC_UPLOAD_DATA
- REQ_REDIRECT_FOLLOW

### URI format 
- Follow this: https://en.wikipedia.org/wiki/Uniform_Resource_Identifier

## Todo  
- [x] Support URI parser
- [x] Follow redirect
- [x] Support SSL
- [ ] Support Basic Auth
- [ ] Support set post field
- [ ] Support Upload multipart
- [ ] Support Cookie

## Known Issues 
- Memory leak
- Uri parse need more work

## Authors
- [Tuan PM](https://twitter.com/tuanpmt)
