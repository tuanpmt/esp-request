#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "list.h"

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
    return root->next;
}
void list_remove(list_t *root, list_t *tree)
{
	list_t *found = root;
	while (found != NULL) {
		if (found == tree) {
			break;
		}
		found = found->next;
	}
	if (found != NULL && found != root) {
		if (found->next && found->prev) {
			found->prev->next = found->next;
			found->next->prev = found->prev;
		} else if (found->next) {
			found->next->prev = NULL;
		} else if (found->prev) {
			found->prev->next = NULL;
		}
		free(found);
	}
}

void list_clear(list_t *root)
{
    //FIXME: Need to test this function
    list_t *found;
    while((found = list_get_first(root)) != NULL) {
        list_remove(root, found);
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
    list_t *new_key = calloc(1, sizeof(list_t));
    if (new_key == NULL)
        return NULL;
    new_key->key = calloc(1, strlen(key) + 1);
    strcpy(new_key->key, key);
    new_key->value = calloc(1, strlen(value)+1);
    strcpy(new_key->value, value);
    return new_key;
}
list_t *list_set_from_string(list_t *root, const char *data)
{
    int len = strlen(data);
    char* eq_ch = strchr(data, ':');
    int key_len, value_len;

    if (eq_ch == NULL)
        return NULL;
    key_len = eq_ch - data;
    value_len = len - key_len - 1;

    char *key = calloc(1, key_len + 1);
    char *value = calloc(1, value_len + 1);
    memcpy(key, data, key_len);
    memcpy(value, eq_ch + 1, value_len);

    return list_set_key(root, trimwhitespace(key), trimwhitespace(value));
}
list_t *list_clear_key(list_t *root, const char *key)
{
    return NULL;
}