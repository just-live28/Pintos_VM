#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_page {
    size_t swap_slot;
};

struct lock swap_lock;
int *slot_refcnt;
#define SECTORS_PER_PAGE 8
#define INVALID_SWAP_SLOT SIZE_MAX

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
