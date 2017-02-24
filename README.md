# Lightweight HTTP client for ESP32 
## Example 

```cpp
int download_callback(request_t *req, char *data, int len)
{
    list_t *found = req->response->header;
    while(found->next != NULL) {
        found = found->next;
        ESP_LOGI(TAG,"Response header %s:%s", (char*)found->key, (char*)found->value);
    }
    //or 
    found = list_get_key(req->response->header, "Content-Length");
    if(found) {
        ESP_LOGI(TAG,"Get header %s:%s", (char*)found->key, (char*)found->value);
    }
    ESP_LOGI(TAG,"%s", data);
    return 0;
}
static void request_task(void *pvParameters)
{
    request_t *req;
    int status;
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
    ESP_LOGI(TAG, "Connected to AP, freemem=%d",esp_get_free_heap_size());
    // vTaskDelay(1000/portTICK_RATE_MS);
    req = req_new("http://httpbin.org/post"); 
    //or
    //request *req = req_new("https://google.com"); //for SSL
    req_setopt(req, REQ_SET_METHOD, "POST");
    req_setopt(req, REQ_SET_POSTFIELDS, "test=data&test2=data2");
    req_setopt(req, REQ_FUNC_DOWNLOAD_CB, download_callback);
    status = req_perform(req);
    req_clean(req);
    vTaskDelete(NULL);
}

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
