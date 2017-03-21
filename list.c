/*
* @2017
* Tuan PM <tuanpm at live dot com>
*/
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "list.h"
#include "esp_log.h"
#define LIST_TAG "LIST"
static char *trimwhitespace(char *str)
{
  char *end;

  // Trim leading space
  while(isspace((unsigned char)*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}
void list_add(list_t *root, list_t *new_tree)
{
    list_t *last = list_get_last(root);
    if(last != NULL) {
        last->next = new_tree;
        new_tree->prev = last;
    }
}
list_t *list_get_last(list_t *root)
{
    list_t *last;
    if(root == NULL)
        return NULL;
    last = root;
    while(last->next != NULL) {
        last = last->next;
    }
    return last;
}
list_t *list_get_first(list_t *root)
{
    if(root == NULL)
        return NULL;
    if(root->next == NULL)
        return NULL;
    // ESP_LOGI(LIST_TAG, "root->next = %x", (int)root->next);
    return root->next;
}
void list_remove(list_t *tree)
{
	list_t *found = tree;
	if (found != NULL) {
		if (found->next && found->prev) {
            // ESP_LOGI(LIST_TAG, "found->prev->next= %x, found->next->prev=%x", (int)found->prev->next, (int)found->next->prev);
			found->prev->next = found->next;
			found->next->prev = found->prev;
		} else if (found->next) {
            // ESP_LOGI(LIST_TAG, "found->next->prev= %x", (int)found->next->prev);
			found->next->prev = NULL;
		} else if (found->prev) {
            // ESP_LOGI(LIST_TAG, "found->prev->next =%x", (int)found->prev->next);
			found->prev->next = NULL;
		}
        free(found->key);
        free(found->value);
		free(found);
	}
}

void list_clear(list_t *root)
{
    //FIXME: Need to test this function
    list_t *found;
    while((found = list_get_first(root)) != NULL) {
        // ESP_LOGI(LIST_TAG, "free key=%s, value=%s, found=%x", (char*)found->key, (char*)found->value, (int)found);
        list_remove(found);
    }
}

list_t *list_set_key(list_t *root, const char *key, const char *value)
{
    list_t *found;
    if(root == NULL)
        return NULL;
    found = root;
    while(found->next != NULL) {
        found = found->next;
        if (strcasecmp(found->key, key) == 0) {
            if (found->value) {
                free(found->value);
            }
            found->value = calloc(1, strlen(value)+1);
            strcpy(found->value, value);
            return found;
        }
    }
    list_t *new_tree = calloc(1, sizeof(list_t));
    if (new_tree == NULL)
        return NULL;
    new_tree->key = calloc(1, strlen(key) + 1);
    strcpy(new_tree->key, key);
    new_tree->value = calloc(1, strlen(value)+1);
    strcpy(new_tree->value, value);

    list_add(root, new_tree);
    return new_tree;
}
list_t *list_get_key(list_t *root, const char *key)
{
    list_t *found;
    if(root == NULL)
        return NULL;
    found = root;
    while(found->next != NULL) {
        found = found->next;
        if (strcasecmp(found->key, key) == 0) {
            return found;
        }
    }
    return NULL;
}
int list_check_key(list_t *root, const char *key, const char *value)
{
    list_t *found = list_get_key(root, key);
    if(found && strcasecmp(found->value, value) == 0)
        return 1;
    return 0;

}
list_t *list_set_from_string(list_t *root, const char *data)
{
    int len = strlen(data);
    char* eq_ch = strchr(data, ':');
    int key_len, value_len;
    list_t *ret = NULL;

    if (eq_ch == NULL)
        return NULL;
    key_len = eq_ch - data;
    value_len = len - key_len - 1;

    char *key = calloc(1, key_len + 1);
    char *value = calloc(1, value_len + 1);
    memcpy(key, data, key_len);
    memcpy(value, eq_ch + 1, value_len);

    ret = list_set_key(root, trimwhitespace(key), trimwhitespace(value));
    free(key);
    free(value);
    return ret;
}
list_t *list_clear_key(list_t *root, const char *key)
{
    return NULL;
}
