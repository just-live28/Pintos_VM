/* vm.c: Generic interface for virtual memory objects. */

#include <stdint.h>
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/uninit.h"
#include "vm/anon.h"

#define STACK_LIMIT (1 << 20)  // 1MB 제한

static struct list frame_table;
static struct lock frame_lock;
static struct list_elem *clock_hand = NULL;	// 리스트 순회 포인터

static uint64_t page_hash (const struct hash_elem *e, void *aux);
static bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void page_destructor (struct hash_elem *e, void *aux);
struct page *page_duplicate_meta_only(struct page *src);
bool page_insert(struct supplemental_page_table *spt, struct page *page);

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
	/* DO NOT MODIFY UPPER LINES. */
	list_init (&frame_table);
    lock_init (&frame_lock);
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

	if (spt_find_page (spt, upage) != NULL)
		return false;

	struct page *page = malloc(sizeof(struct page));
	if (page == NULL)
		return false;

	bool (*page_initializer)(struct page *, enum vm_type, void *) = NULL;
	switch (VM_TYPE(type)) {
		case VM_ANON:
			page_initializer = anon_initializer;
			break;
		case VM_FILE:
			page_initializer = file_backed_initializer;
			break;
	}

	uninit_new(page, upage, init, type, aux, page_initializer);
	page->writable = writable;

	if (!spt_insert_page(spt, page)) {
		free(page);
		return false;
	}

	return true;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page p;
	p.va = pg_round_down(va);
	struct hash_elem *e = hash_find (&spt->hash, &p.hash_elem);
	
	if (e != NULL) {
		return hash_entry (e, struct page, hash_elem);
	} else {
		return NULL;
	}
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	struct hash_elem *e = hash_insert (&spt->hash, &page->hash_elem);
	return e == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	if (page == NULL) return;
	hash_delete (&spt->hash, &page->hash_elem);
	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	static int full_loop = 0;	// 무한루프 감지용
	lock_acquire(&frame_lock);

	/* 핸들 초기화 (리스트 첫 원소) */
	if (clock_hand == NULL || clock_hand == list_end(&frame_table)) {
		clock_hand = list_begin(&frame_table);
	}

	while (true) {
		struct frame *f = list_entry (clock_hand, struct frame, elem);

		/* 다음 원소 위치를 미리 계산해야, 현재 clock hand를 삭제해도 안전 */
		struct list_elem *next = list_next(clock_hand);
		if (next == list_end(&frame_table)) {
			next = list_begin(&frame_table);
		}

		/* 후보 검증 */
		if (!f->pinned && f->page != NULL) {
			/* 최근에 쓰인 적이 있다면 기회 한 번 더 부여 */
			if (pml4_is_accessed(f->owner->pml4, f->page->va)) {
				pml4_set_accessed(f->owner->pml4, f->page->va, false);
			} else {
				/* 2-nd chance 탈락, victim 확정 */
				full_loop = 0;
				list_remove (clock_hand);
				clock_hand = next;
				lock_release(&frame_lock);
				return f;
			}
		}

		clock_hand = next;

		if (clock_hand == list_begin (&frame_table)) {
			if (++full_loop > 1)
				PANIC ("all frames are pinned");
		}
	}
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	struct page *page = victim->page;
	ASSERT(page != NULL);

	/* 매핑 해제 */
	pml4_clear_page(victim->owner->pml4, page->va);
	page->frame = NULL;

	/* Swap out. 디스크 I/O만 담당 */
	ASSERT(page->operations->swap_out != NULL);
	swap_out(page);

	/* victim frame 재활용 준비 */
	victim->page = NULL;
	victim->pinned = false;

	/* owner는 그대로 유지, 새 claim 시점에 덮어쓰기 */
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = malloc(sizeof(struct frame));
	ASSERT (frame != NULL);

	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

	if (frame->kva == NULL) {
		frame = vm_evict_frame();
	} else {
		lock_acquire(&frame_lock);
		list_push_back(&frame_table, &frame->elem);
		lock_release(&frame_lock);
	}

	frame->page = NULL;
	frame->pinned = false;
	frame->owner = thread_current();

	return frame;
}

void vm_frame_free (struct frame *f) {
	// 연결 끊기
	ASSERT (f != NULL);
	if (f->page) {
		f->page->frame = NULL;
	}

	// frame_table에서 제거 (전후로 락 설정)
	lock_acquire(&frame_lock);
	list_remove(&f->elem);
	lock_release(&frame_lock);

	// 물리 페이지 반환 및 프레임 구조체 해제
	palloc_free_page(f->kva);
	free(f);
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr) {
	if ((uintptr_t)USER_STACK - (uintptr_t) addr > STACK_LIMIT) 
		return false;

	if (!vm_alloc_page_with_initializer(VM_ANON, addr, true, NULL, NULL))
		return false;

	return vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
               bool user, bool write, bool not_present) {
       struct supplemental_page_table *spt = &thread_current ()->spt;

       // 이후 cow 확장 시 page && ! not_present에 대해 return false해야 함
       if (addr == NULL || is_kernel_vaddr(addr))
               return false;

       struct page *page = spt_find_page(spt, addr);

       if (page == NULL) {
               if (not_present && addr >= f->rsp - 32 && addr < USER_STACK)
                       return vm_stack_growth(addr);
               return false;
       }

       if (not_present) {
               if (write && !page->writable)
                       return false;
               return vm_do_claim_page(page);
       }

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
vm_claim_page (void *va) {
	struct page *page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	if (frame == NULL)
		return false;

	frame->page = page;
	page->frame = frame;

	if (!swap_in(page, frame->kva)) {
		frame->page = NULL;
		page->frame = NULL;
		vm_frame_free(frame);
		return false;
	}

	if (!pml4_set_page (thread_current()->pml4, page->va, frame->kva, page->writable)) {
		frame->page = NULL;
		page->frame = NULL;
		vm_frame_free (frame);
		return false;
	}

	pml4_set_dirty(thread_current()->pml4, page->va, false);
	frame->owner = thread_current();	// 이후 evict 후에 재활용 시 꼭 덮어쓸 것
	return true;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init(&spt->hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct hash_iterator it;
	hash_first(&it, &src->hash);

	while (hash_next(&it)) {
		struct page *sp = hash_entry(hash_cur(&it), struct page, hash_elem);
		enum vm_type stype = page_get_type(sp);
		
                if (stype == VM_UNINIT) {
                        struct page *page = malloc(sizeof(struct page));
                        if (page == NULL)
                                return false;

                        void *aux_copy = sp->uninit.aux;

                        if (VM_TYPE(sp->uninit.type) == VM_FILE && sp->uninit.aux != NULL) {
                                struct lazy_load_info *info = malloc(sizeof(struct lazy_load_info));
                                if (info == NULL) {
                                        free(page);
                                        return false;
                                }
                                memcpy(info, sp->uninit.aux, sizeof(struct lazy_load_info));
                                aux_copy = info;
                        }

                        uninit_new(page, sp->va, sp->uninit.init, sp->uninit.type, aux_copy,
                           sp->uninit.page_initializer);
                        page->writable = sp->writable;
                        if (!spt_insert_page(dst, page)) {
                                if (VM_TYPE(sp->uninit.type) == VM_FILE && aux_copy != NULL)
                                        free(aux_copy);
                                free(page);
                                return false;
                        }
                } else {
			if (vm_alloc_page(stype, sp->va, sp->writable) &&
				vm_claim_page(sp->va)) {
				struct page *dp = spt_find_page(dst, sp->va);
				memcpy(dp->frame->kva, sp->frame->kva, PGSIZE);
			}
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	if (spt == NULL) return;
	hash_clear(&spt->hash, page_destructor);
}

static void
page_destructor (struct hash_elem *e, void *aux) {
    struct page *page = hash_entry (e, struct page, hash_elem);
    destroy (page);
	free(page);
}

/* 주어진 페이지의 고유한 해시 값 계산 */
static uint64_t
page_hash (const struct hash_elem *e, void *aux) {
  const struct page *p = hash_entry (e, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* 해시 테이블 내 원소들을 정렬할 때 사용하는 비교 함수 (해시 충돌 발생 시 사용) */
static bool
page_less (const struct hash_elem *a,
           const struct hash_elem *b,
           void *aux) {
  const struct page *pa = hash_entry (a, struct page, hash_elem);
  const struct page *pb = hash_entry (b, struct page, hash_elem);
  return pa->va < pb->va;
}