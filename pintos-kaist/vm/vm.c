/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"

uint64_t page_hash(const struct hash_elem *e, void *aux);
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);
void hash_page_destroy(struct hash_elem *e, void *aux);
static bool vm_copy_claim_page(struct supplemental_page_table *dst, void *va, void *kva, bool writable);

struct list frame_table;
struct lock frame_lock;
struct list_elem *next = NULL;	// victim 선정용 전역 포인터

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	list_init(&frame_table);
	lock_init(&frame_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {

		/** #project3-Anonymous Page */
		struct page *page = malloc(sizeof(struct page));

		if (!page)
			return false;

		typedef bool (*initializer_by_type)(struct page *, enum vm_type, void *);
		initializer_by_type initializer = NULL;

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			initializer = anon_initializer;
			break;
		case VM_FILE:
			initializer = file_backed_initializer;
			break;
		}

		uninit_new(page, upage, init, type, aux, initializer);
		page->writable = writable;
		
		return spt_insert_page(spt, page);
	}
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page page;
    page.va = pg_round_down(va);
    struct hash_elem *e = hash_find(&spt->spt_hash, &page.hash_elem);

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	return hash_insert (&spt->spt_hash, &page->hash_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->spt_hash, &page->hash_elem);
	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	lock_acquire(&frame_lock);
	for (next = list_begin(&frame_table); next != list_end(&frame_table); next = list_next(next))
	{
		victim = list_entry(next, struct frame, frame_elem);
		if (pml4_is_accessed(thread_current()->pml4, victim->page->va)) {
			pml4_set_accessed(thread_current()->pml4, victim->page->va, false);
		} else {
			lock_release(&frame_lock);
			return victim;
		}
	}
	lock_release(&frame_lock);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	if (victim->page)
		swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	ASSERT (frame != NULL);

	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);  

    if (frame->kva == NULL) {
        frame = vm_evict_frame();  
	} else {
		lock_acquire(&frame_lock);
        list_push_back(&frame_table, &frame->frame_elem);
		lock_release(&frame_lock);
	}

    frame->page = NULL;

	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr UNUSED) {
    bool success = false;
	addr = pg_round_down(addr);
    if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true)) {
        success = vm_claim_page(addr);

        if (success) {
			return true;
        }
    }
	return false;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	/** Project 3-Copy On Write */
    if (!page->accessible)
        return false;

    void *kva = page->frame->kva;

    page->frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

    if (page->frame->kva == NULL)
        page->frame = vm_evict_frame();  
		
    memcpy(page->frame->kva, kva, PGSIZE);

    if (!pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->accessible))
        return false;

    return true;
}

/* 스택은 최대 1 MiB, USER_STACK 기준 아래로 확장할 수 있다. */
#define STACK_LIMIT (USER_STACK - (1 << 20))   /* (= USER_STACK-1 MiB) */

/* 최대 몇 바이트까지 rsp 아래 접근을 스택 성장으로 허용할지. 
   8 바이트(단일 push) + 여유를 주고 싶다면 32로 늘릴 수 있다. */
#define STACK_GROW_GAP 32

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *fault_addr,
                     bool user, bool write, bool not_present)
{
    struct thread *t = thread_current ();
    struct supplemental_page_table *spt = &t->spt;

    if (fault_addr == NULL || is_kernel_vaddr (fault_addr))
        return false;

    struct page *page = spt_find_page (spt, fault_addr);

    if (!not_present && write)
        return vm_handle_wp(page);

    if (page != NULL) {
        if (write && !page->writable)
            return false;
        return vm_do_claim_page (page);
    }

    void *rsp = user ? f->rsp : t->stack_pointer;
    bool can_grow =
        fault_addr >= STACK_LIMIT &&
        fault_addr <  USER_STACK &&
        fault_addr >= rsp - 32;

    if (can_grow)
        return vm_stack_growth (fault_addr);

    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = spt_find_page(&thread_current()->spt, va);

    if (page == NULL)
        return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
        return false;

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
	struct hash_iterator i;
	hash_first(&i, &src->spt_hash);
	while (hash_next(&i))
	{
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
        bool writable = src_page->writable;

		if (type == VM_UNINIT)
		{
			vm_alloc_page_with_initializer(
				src_page->uninit.type,
				src_page->va,
				src_page->writable,
				src_page->uninit.init,
				src_page->uninit.aux);
		}
		else if (type == VM_FILE) {
            struct lazy_load_arg *aux = malloc(sizeof(struct lazy_load_arg));
            aux->file = src_page->file.file;
            aux->ofs = src_page->file.ofs;
            aux->read_bytes = src_page->file.read_bytes;

            if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, aux))
                return false;

            struct page *dst_page = spt_find_page(dst, upage);
            file_backed_initializer(dst_page, type, NULL);
            dst_page->frame = src_page->frame;
            pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, src_page->writable);
        }
		else {
			if (!vm_alloc_page(type, upage, writable))
				return false;
			
			if (!vm_copy_claim_page(dst, upage, src_page->frame->kva, writable))
				return false;

		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	hash_clear(&spt->spt_hash, hash_page_destroy);
}

uint64_t 
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

bool page_less(const struct hash_elem *a_,
               const struct hash_elem *b_, void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

void 
hash_page_destroy(struct hash_elem *e, void *aux)
{
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);
}

static bool 
vm_copy_claim_page(struct supplemental_page_table *dst, void *va, void *kva, bool writable) {
    struct page *page = spt_find_page(dst, va);

    if (page == NULL)
        return false;

    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));

    if (!frame)
        return false;

    page->accessible = writable; 
    frame->page = page;
    page->frame = frame;
    frame->kva = kva;

    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, false)) {
        free(frame);
        return false;
    }

    list_push_back(&frame_table, &frame->frame_elem); 

    return swap_in(page, frame->kva);
}