/* Public domain. */

#ifndef __DRMCOMPAT_LINUX_LLIST_H__
#define	__DRMCOMPAT_LINUX_LLIST_H__

#include <machine/atomic.h>

struct llist_node {
	struct llist_node *next;
} __subobject_use_container_bounds;

struct llist_head {
	struct llist_node *first;
};

#define llist_entry(ptr, type, member) \
	((ptr) ? container_of(ptr, type, member) : NULL)

static inline struct llist_node *
llist_del_all(struct llist_head *head)
{
	return (struct llist_node *)atomic_swap_ptr((uintptr_t *)&head->first, (uint64_t)NULL);
}

static inline struct llist_node *
llist_del_first(struct llist_head *head)
{
	struct llist_node *first, *next;

	do {
		first = head->first;
		if (first == NULL)
			return NULL;
		next = first->next;
	} while (atomic_fcmpset_ptr((uintptr_t *)&head->first, (uintptr_t *)first, (uint64_t)next) != 0);

	return first;
}

static inline bool
llist_add(struct llist_node *new, struct llist_head *head)
{
	struct llist_node *first;

	do {
		new->next = first = head->first;
	} while (atomic_fcmpset_ptr((uintptr_t *)&head->first, (uintptr_t *)first, (uint64_t)new) != 0);

	return (first == NULL);
}

static inline void
init_llist_head(struct llist_head *head)
{
	head->first = NULL;
}

static inline bool
llist_empty(struct llist_head *head)
{
	return (head->first == NULL);
}

#define llist_for_each_entry_safe(pos, n, node, member) 		\
	for (pos = llist_entry((node), __typeof(*pos), member); 	\
	    pos != NULL &&						\
	    (n = llist_entry(pos->member.next, __typeof(*pos), member), pos); \
	    pos = n)

#endif	/* __DRMCOMPAT_LINUX_LLIST_H__ */
