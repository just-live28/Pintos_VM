/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <bitmap.h>	// bitmap
#include "vm/vm.h"
#include "threads/vaddr.h"	// PGSIZE
#include <string.h>	// memset
#include "devices/disk.h"

static struct bitmap *swap_table;
struct lock swap_lock;
int *slot_refcnt;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	swap_disk = disk_get(1, 1);
	size_t swap_size = disk_size(swap_disk) / SECTORS_PER_PAGE;
	swap_table = bitmap_create(swap_size);
	slot_refcnt = calloc(swap_size, sizeof(int));
	lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
	anon_page->swap_slot = INVALID_SWAP_SLOT;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	size_t slot = anon_page->swap_slot;

	if (slot == INVALID_SWAP_SLOT) {
		memset(kva, 0, PGSIZE);
		return true;
	}

	lock_acquire(&swap_lock);
	disk_sector_t base_sector = slot * SECTORS_PER_PAGE;
	for (int i = 0; i < SECTORS_PER_PAGE; i++) {
		disk_read(swap_disk, base_sector + i, kva + i * DISK_SECTOR_SIZE);
	}
	if (--slot_refcnt[slot] == 0) {
		bitmap_reset(swap_table, anon_page->swap_slot);
	}
	lock_release(&swap_lock);

	anon_page->swap_slot = INVALID_SWAP_SLOT;
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	lock_acquire(&swap_lock);
	size_t slot = bitmap_scan_and_flip(swap_table, 0, bitmap_size(swap_table), false);

	if (slot == BITMAP_ERROR)
		return false; // swap 공간 부족

	disk_sector_t base_sector = slot * SECTORS_PER_PAGE;
	uint8_t *kva = page->frame->kva;

	for (int i = 0; i < SECTORS_PER_PAGE; i++) {
		disk_write(swap_disk, base_sector + i, kva + i * DISK_SECTOR_SIZE);
	}
	anon_page->swap_slot = slot;
	page->frame = NULL;
	slot_refcnt[slot] = 1;
	lock_release(&swap_lock);

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	size_t slot = anon_page->swap_slot;

	if (slot != INVALID_SWAP_SLOT) {
		lock_acquire(&swap_lock);
		if (--slot_refcnt[slot] == 0) {
			bitmap_reset(swap_table, slot);
		}
		lock_release(&swap_lock);

		anon_page->swap_slot = INVALID_SWAP_SLOT;
	}
}
