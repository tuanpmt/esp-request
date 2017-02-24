#ifndef _LIST_H
#define _LIST_H

typedef struct list_t {
	void *key;
	void *value;
	struct list_t *next;
	struct list_t *prev;
} list_t;

void list_add(list_t *root, list_t *new_tree);
list_t *list_get_last(list_t *root);
list_t *list_get_first(list_t *root);
void list_remove(list_t *tree);
void list_clear(list_t *root);
list_t *list_set_key(list_t *root, const char *key, const char *value);
list_t *list_get_key(list_t *root, const char *key);
int list_check_key(list_t *root, const char *key, const char *value);
list_t *list_set_from_string(list_t *root, const char *data); //data = "key=value"
#endif
