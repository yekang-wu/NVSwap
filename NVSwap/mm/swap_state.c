/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>
#include <linux/page_cgroup.h>

#include <asm/pgtable.h>
#include <linux/rmap.h>
#include <linux/sched.h>

unsigned int swapOutRecord_span = 0;
unsigned int swapOutRecord_span_2 = 0;
unsigned int swapOutRecord_span_3 = 0;
unsigned int swapOutRecord_span_4 = 0;
unsigned int swapOutRecord_span_5 = 0;
unsigned int swapOutRecord_span_6 = 0;
unsigned int swapOutRecord_span_7 = 0;

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_page_list.
 */
static const struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.set_page_dirty	= __set_page_dirty_no_writeback,
	.migratepage	= migrate_page,
};

static struct backing_dev_info swap_backing_dev_info = {
	.name		= "swap",
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK | BDI_CAP_SWAP_BACKED,
};

struct address_space swapper_space = {
	.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
	.tree_lock	= __SPIN_LOCK_UNLOCKED(swapper_space.tree_lock),
	.a_ops		= &swap_aops,
	.i_mmap_nonlinear = LIST_HEAD_INIT(swapper_space.i_mmap_nonlinear),
	.backing_dev_info = &swap_backing_dev_info,
};

#define INC_CACHE_INFO(x)	do { swap_cache_info.x++; } while (0)

static struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
} swap_cache_info;

void show_swap_cache_info(void)
{
	printk("%lu pages in swap cache\n", total_swapcache_pages);
	printk("Swap cache stats: add %lu, delete %lu, find %lu/%lu\n",
		swap_cache_info.add_total, swap_cache_info.del_total,
		swap_cache_info.find_success, swap_cache_info.find_total);
	printk("Free swap  = %ldkB\n", nr_swap_pages << (PAGE_SHIFT - 10));
	printk("Total swap = %lukB\n", total_swap_pages << (PAGE_SHIFT - 10));
}

/*
 * __add_to_swap_cache resembles add_to_page_cache_locked on swapper_space,
 * but sets SwapCache flag and private instead of mapping and index.
 */
static int __add_to_swap_cache(struct page *page, swp_entry_t entry)
{
	int error;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(PageSwapCache(page));
	VM_BUG_ON(!PageSwapBacked(page));

	page_cache_get(page);
	SetPageSwapCache(page);
	set_page_private(page, entry.val);

	spin_lock_irq(&swapper_space.tree_lock);
	error = radix_tree_insert(&swapper_space.page_tree, entry.val, page);
	if (likely(!error)) {
		total_swapcache_pages++;
		__inc_zone_page_state(page, NR_FILE_PAGES);
		INC_CACHE_INFO(add_total);
	}
	spin_unlock_irq(&swapper_space.tree_lock);

	if (unlikely(error)) {
		/*
		 * Only the context which have set SWAP_HAS_CACHE flag
		 * would call add_to_swap_cache().
		 * So add_to_swap_cache() doesn't returns -EEXIST.
		 */
		VM_BUG_ON(error == -EEXIST);
		set_page_private(page, 0UL);
		ClearPageSwapCache(page);
		page_cache_release(page);
	}

	return error;
}


int add_to_swap_cache(struct page *page, swp_entry_t entry, gfp_t gfp_mask)
{
	int error;

	error = radix_tree_preload(gfp_mask);
	if (!error) {
		error = __add_to_swap_cache(page, entry);
		radix_tree_preload_end();
	}
	return error;
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache.
 */
void __delete_from_swap_cache(struct page *page)
{
	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(!PageSwapCache(page));
	VM_BUG_ON(PageWriteback(page));

	radix_tree_delete(&swapper_space.page_tree, page_private(page));
	set_page_private(page, 0);
	ClearPageSwapCache(page);
	total_swapcache_pages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);
	INC_CACHE_INFO(del_total);
}

/**
 * add_to_swap - allocate swap space for a page
 * @page: page we want to move to swap
 *
 * Allocate swap space for the page and add the page to the
 * swap cache.  Caller needs to hold the page lock. 
 */
int add_to_swap(struct page *page)
{
	swp_entry_t entry;
	int err;
	unsigned int hybrid_mem_ratio = hybrid_task_ratio;
	unsigned int hybrid_ssd_ratio = 100-hybrid_task_ratio;
	unsigned int hybrid_mem_ratio_2 = hybrid_task_ratio_2;
	unsigned int hybrid_ssd_ratio_2 = 100-hybrid_task_ratio_2;
	unsigned int hybrid_mem_ratio_3 = hybrid_task_ratio_3;
	unsigned int hybrid_ssd_ratio_3 = 100-hybrid_task_ratio_3;
	unsigned int hybrid_mem_ratio_4 = hybrid_task_ratio_4;
	unsigned int hybrid_ssd_ratio_4 = 100-hybrid_task_ratio_4;
	unsigned int hybrid_mem_ratio_5 = hybrid_task_ratio_5;
	unsigned int hybrid_ssd_ratio_5 = 100-hybrid_task_ratio_5;
	unsigned int hybrid_mem_ratio_6 = hybrid_task_ratio_6;
	unsigned int hybrid_ssd_ratio_6 = 100-hybrid_task_ratio_6;
	unsigned int hybrid_mem_ratio_7 = hybrid_task_ratio_7;
	unsigned int hybrid_ssd_ratio_7 = 100-hybrid_task_ratio_7;
	int hybrid_dest_flag = 0;
	int hybrid_dest_flag_2 = 0;
	int hybrid_dest_flag_3 = 0;
	int hybrid_dest_flag_4 = 0;
	int hybrid_dest_flag_5 = 0;
	int hybrid_dest_flag_6 = 0;
	int hybrid_dest_flag_7 = 0;
    
	// [wyk] Reverse mapping
	struct anon_vma *anon_vma = NULL;
	struct anon_vma_chain *avc = NULL;
	int pid_exist_flag = 0, pid_exist_flag_2 = 0, pid_exist_flag_3 = 0, pid_exist_flag_4 = 0, pid_exist_flag_5 = 0, pid_exist_flag_6 = 0, pid_exist_flag_7 = 0;

	//--------------------------------------------------------------------------------------------
	//reverse mapping
	if(hybrid_mode > 0) {
		anon_vma = page_lock_anon_vma(page);
		if (anon_vma != NULL){
			list_for_each_entry(avc, &anon_vma->head, same_anon_vma) {
				if (avc->vma != NULL){
					if (avc->vma->vm_mm != NULL){
						if (avc->vma->vm_mm->owner != NULL){
							if (avc->vma->vm_mm->owner->pid==hybrid_task_pid){
								pid_exist_flag=1;
								swapOutRecord_count++;
								if (swapOutRecord_status_begin==1){
									//swapOutRecord_span++;
									//if(swapOutRecord_span>=100){
									//	swapOutRecord_span=0;
										SwapOutRecord_AddStartT(page);
									//}
								}
							} else if (avc->vma->vm_mm->owner->pid==hybrid_task_pid_2){
								pid_exist_flag_2=1;
								swapOutRecord_count_2++;
								if (swapOutRecord_status_begin_2==1){
									//swapOutRecord_span_2++;
									//if(swapOutRecord_span_2>=100){
									//	swapOutRecord_span_2=0;
										SwapOutRecord_AddStartT_2(page);
									//}
								}
							} else if (avc->vma->vm_mm->owner->pid==hybrid_task_pid_3){
								pid_exist_flag_3=1;
								swapOutRecord_count_3++;
								if (swapOutRecord_status_begin_3==1){
									//swapOutRecord_span_3++;
									//if(swapOutRecord_span_3>=100){
									//	swapOutRecord_span_3=0;
										SwapOutRecord_AddStartT_3(page);
									//}
								}
							} else if (avc->vma->vm_mm->owner->pid==hybrid_task_pid_4){
								pid_exist_flag_4=1;
								swapOutRecord_count_4++;
								if (swapOutRecord_status_begin_4==1){
									//swapOutRecord_span_4++;
									//if(swapOutRecord_span_4>=100){
									//	swapOutRecord_span_4=0;
										SwapOutRecord_AddStartT_4(page);
									//}
								}
							} else if (avc->vma->vm_mm->owner->pid==hybrid_task_pid_5){
								pid_exist_flag_5=1;
								swapOutRecord_count_5++;
								if (swapOutRecord_status_begin_5==1){
									//swapOutRecord_span_5++;
									//if(swapOutRecord_span_5>=100){
									//	swapOutRecord_span_5=0;
										SwapOutRecord_AddStartT_5(page);
									//}
								}
							} else if (avc->vma->vm_mm->owner->pid==hybrid_task_pid_6){
								pid_exist_flag_6=1;
								swapOutRecord_count_6++;
								if (swapOutRecord_status_begin_6==1){
									//swapOutRecord_span_6++;
									//if(swapOutRecord_span_6>=100){
									//	swapOutRecord_span_6=0;
										SwapOutRecord_AddStartT_6(page);
									//}
								}
							} else if (avc->vma->vm_mm->owner->pid==hybrid_task_pid_7){
								pid_exist_flag_7=1;
								swapOutRecord_count_7++;
								if (swapOutRecord_status_begin_7==1){
									//swapOutRecord_span_7++;
									//if(swapOutRecord_span_7>=100){
									//	swapOutRecord_span_7=0;
										SwapOutRecord_AddStartT_7(page);
									//}
								}
							}
							break;
						}
					}
				}
			}
		}
		page_unlock_anon_vma(anon_vma);
	}
//--------------------------------------------------------------------------------------------

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(!PageUptodate(page));

	//if(hybrid_mode == 1 && task_ptr->pid == hybrid_task_pid){
	if(pid_exist_flag == 1){

		// [wyk] device 1: SSD, device 2: MEM_SWAP
		if(hybrid_mem_ratio == 100){
			entry = get_swap_page_hybrid(2-1);
			hybrid_dest_flag = 2;
		}else if(hybrid_mem_ratio == 0){
			entry = get_swap_page_hybrid(1-1);
			hybrid_dest_flag = 1;
		}else{
			if(hybrid_ssd_unit < hybrid_ssd_ratio){ //[wyk] to SSD
				hybrid_ssd_unit++;
				entry = get_swap_page_hybrid(1-1);
				hybrid_dest_flag = 1;
			}else{									//[wyk] to NVM_SWAP
				hybrid_mem_unit++;
				if(hybrid_mem_unit>=hybrid_mem_ratio){
					hybrid_ssd_unit=0;
					hybrid_mem_unit=0;
				}
				entry = get_swap_page_hybrid(2-1);
				hybrid_dest_flag = 2;
			}
		}
	}else if(pid_exist_flag_2 == 1){

        // [wyk] device 1: SSD, device 2: MEM_SWAP
        if(hybrid_mem_ratio_2 == 100){
            entry = get_swap_page_hybrid(2-1);
            hybrid_dest_flag_2 = 2;
        }else if(hybrid_mem_ratio_2 == 0){
            entry = get_swap_page_hybrid(1-1);
            hybrid_dest_flag_2 = 1;
        }else{
			if(hybrid_ssd_unit_2 < hybrid_ssd_ratio_2){ //[wyk] to SSD
				hybrid_ssd_unit_2++;
				entry = get_swap_page_hybrid(1-1);
				hybrid_dest_flag_2 = 1;
			}else{									//[wyk] to NVM_SWAP
				hybrid_mem_unit_2++;
				if(hybrid_mem_unit_2>=hybrid_mem_ratio_2){
					hybrid_ssd_unit_2=0;
					hybrid_mem_unit_2=0;
				}
				entry = get_swap_page_hybrid(2-1);
				hybrid_dest_flag_2 = 2;
			}
        }
	}else if(pid_exist_flag_3 == 1){

		// [wyk] device 1: SSD, device 2: MEM_SWAP
		if(hybrid_mem_ratio_3 == 100){
			entry = get_swap_page_hybrid(2-1);
			hybrid_dest_flag_3 = 2;
		}else if(hybrid_mem_ratio_3 == 0){
			entry = get_swap_page_hybrid(1-1);
			hybrid_dest_flag_3 = 1;
		}else{
			if(hybrid_ssd_unit_3 < hybrid_ssd_ratio_3){ //[wyk] to SSD
				hybrid_ssd_unit_3++;
				entry = get_swap_page_hybrid(1-1);
				hybrid_dest_flag_3 = 1;
			}else{									//[wyk] to NVM_SWAP
				hybrid_mem_unit_3++;
				if(hybrid_mem_unit_3>=hybrid_mem_ratio_3){
					hybrid_ssd_unit_3=0;
					hybrid_mem_unit_3=0;
				}
				entry = get_swap_page_hybrid(2-1);
				hybrid_dest_flag_3 = 2;
			}
		}
	}else if(pid_exist_flag_4 == 1){

		// [wyk] device 1: SSD, device 2: MEM_SWAP
		if(hybrid_mem_ratio_4 == 100){
			entry = get_swap_page_hybrid(2-1);
			hybrid_dest_flag_4 = 2;
		}else if(hybrid_mem_ratio_4 == 0){
			entry = get_swap_page_hybrid(1-1);
			hybrid_dest_flag_4 = 1;
		}else{
			if(hybrid_ssd_unit_4 < hybrid_ssd_ratio_4){ //[wyk] to SSD
				hybrid_ssd_unit_4++;
				entry = get_swap_page_hybrid(1-1);
				hybrid_dest_flag_4 = 1;
			}else{									//[wyk] to NVM_SWAP
				hybrid_mem_unit_4++;
				if(hybrid_mem_unit_4>=hybrid_mem_ratio_4){
					hybrid_ssd_unit_4=0;
					hybrid_mem_unit_4=0;
				}
				entry = get_swap_page_hybrid(2-1);
				hybrid_dest_flag_4 = 2;
			}
		}
	}else if(pid_exist_flag_5 == 1){

		// [wyk] device 1: SSD, device 2: MEM_SWAP
		if(hybrid_mem_ratio_5 == 100){
			entry = get_swap_page_hybrid(2-1);
			hybrid_dest_flag_5 = 2;
		}else if(hybrid_mem_ratio_5 == 0){
			entry = get_swap_page_hybrid(1-1);
			hybrid_dest_flag_5 = 1;
		}else{
			if(hybrid_ssd_unit_5 < hybrid_ssd_ratio_5){ //[wyk] to SSD
				hybrid_ssd_unit_5++;
				entry = get_swap_page_hybrid(1-1);
				hybrid_dest_flag_5 = 1;
			}else{									//[wyk] to NVM_SWAP
				hybrid_mem_unit_5++;
				if(hybrid_mem_unit_5>=hybrid_mem_ratio_5){
					hybrid_ssd_unit_5=0;
					hybrid_mem_unit_5=0;
				}
				entry = get_swap_page_hybrid(2-1);
				hybrid_dest_flag_5 = 2;
			}
		}
	}else if(pid_exist_flag_6 == 1){

		// [wyk] device 1: SSD, device 2: MEM_SWAP
		if(hybrid_mem_ratio_6 == 100){
			entry = get_swap_page_hybrid(2-1);
			hybrid_dest_flag_6 = 2;
		}else if(hybrid_mem_ratio_6 == 0){
			entry = get_swap_page_hybrid(1-1);
			hybrid_dest_flag_6 = 1;
		}else{
			if(hybrid_ssd_unit_6 < hybrid_ssd_ratio_6){ //[wyk] to SSD
				hybrid_ssd_unit_6++;
				entry = get_swap_page_hybrid(1-1);
				hybrid_dest_flag_6 = 1;
			}else{									//[wyk] to NVM_SWAP
				hybrid_mem_unit_6++;
				if(hybrid_mem_unit_6>=hybrid_mem_ratio_6){
					hybrid_ssd_unit_6=0;
					hybrid_mem_unit_6=0;
				}
				entry = get_swap_page_hybrid(2-1);
				hybrid_dest_flag_6 = 2;
			}
		}
	}else if(pid_exist_flag_7 == 1){

		// [wyk] device 1: SSD, device 2: MEM_SWAP
		if(hybrid_mem_ratio_7 == 100){
			entry = get_swap_page_hybrid(2-1);
			hybrid_dest_flag_7 = 2;
		}else if(hybrid_mem_ratio_7 == 0){
			entry = get_swap_page_hybrid(1-1);
			hybrid_dest_flag_7 = 1;
		}else{
			if(hybrid_ssd_unit_7 < hybrid_ssd_ratio_7){ //[wyk] to SSD
				hybrid_ssd_unit_7++;
				entry = get_swap_page_hybrid(1-1);
				hybrid_dest_flag_7 = 1;
			}else{									//[wyk] to NVM_SWAP
				hybrid_mem_unit_7++;
				if(hybrid_mem_unit_7>=hybrid_mem_ratio_7){
					hybrid_ssd_unit_7=0;
					hybrid_mem_unit_7=0;
				}
				entry = get_swap_page_hybrid(2-1);
				hybrid_dest_flag_7 = 2;
			}
		}
	}else{
		entry = get_swap_page();
	}

	//entry = get_swap_page();
	if (!entry.val)
		return 0;

	if (unlikely(PageTransHuge(page)))
		if (unlikely(split_huge_page(page))) {
			swapcache_free(entry, NULL);
			return 0;
		}

	/*
	 * Radix-tree node allocations from PF_MEMALLOC contexts could
	 * completely exhaust the page allocator. __GFP_NOMEMALLOC
	 * stops emergency reserves from being allocated.
	 *
	 * TODO: this could cause a theoretical memory reclaim
	 * deadlock in the swap out path.
	 */
	/*
	 * Add it to the swap cache and mark it dirty
	 */
	err = add_to_swap_cache(page, entry,
			__GFP_HIGH|__GFP_NOMEMALLOC|__GFP_NOWARN);

	if (!err) {	/* Success */
		if (hybrid_dest_flag == 1){
			hybrid_ssd_total++;
		} else if (hybrid_dest_flag == 2){
			hybrid_mem_total++;
		}
		
		if (hybrid_dest_flag_2 == 1){
			hybrid_ssd_total_2++;
		} else if (hybrid_dest_flag_2 == 2){
			hybrid_mem_total_2++;
		}
		
		if (hybrid_dest_flag_3 == 1){
			hybrid_ssd_total_3++;
		} else if (hybrid_dest_flag_3 == 2){
			hybrid_mem_total_3++;
		}
		
		if (hybrid_dest_flag_4 == 1){
			hybrid_ssd_total_4++;
		} else if (hybrid_dest_flag_4 == 2){
			hybrid_mem_total_4++;
		}
		
		if (hybrid_dest_flag_5 == 1){
			hybrid_ssd_total_5++;
		} else if (hybrid_dest_flag_5 == 2){
			hybrid_mem_total_5++;
		}
		
		if (hybrid_dest_flag_6 == 1){
			hybrid_ssd_total_6++;
		} else if (hybrid_dest_flag_6 == 2){
			hybrid_mem_total_6++;
		}
		
		if (hybrid_dest_flag_7 == 1){
			hybrid_ssd_total_7++;
		} else if (hybrid_dest_flag_7 == 2){
			hybrid_mem_total_7++;
		}
		SetPageDirty(page);
		return 1;
	} else {	/* -ENOMEM radix-tree allocation failure */
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		 */
		swapcache_free(entry, NULL);
		return 0;
	}
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache and locked.
 * It will never put the page into the free list,
 * the caller has a reference on the page.
 */
void delete_from_swap_cache(struct page *page)
{
	swp_entry_t entry;

	entry.val = page_private(page);

	spin_lock_irq(&swapper_space.tree_lock);
	__delete_from_swap_cache(page);
	spin_unlock_irq(&swapper_space.tree_lock);

	swapcache_free(entry, page);
	page_cache_release(page);
}

/* 
 * If we are the only user, then try to free up the swap cache. 
 * 
 * Its ok to check for PageSwapCache without the page lock
 * here because we are going to recheck again inside
 * try_to_free_swap() _with_ the lock.
 * 					- Marcelo
 */
static inline void free_swap_cache(struct page *page)
{
	if (PageSwapCache(page) && !page_mapped(page) && trylock_page(page)) {
		try_to_free_swap(page);
		unlock_page(page);
	}
}

/* 
 * Perform a free_page(), also freeing any swap cache associated with
 * this page if it is the last user of the page.
 */
void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
	page_cache_release(page);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
void free_pages_and_swap_cache(struct page **pages, int nr)
{
	struct page **pagep = pages;

	lru_add_drain();
	while (nr) {
		int todo = min(nr, PAGEVEC_SIZE);
		int i;

		for (i = 0; i < todo; i++)
			free_swap_cache(pagep[i]);
		release_pages(pagep, todo, 0);
		pagep += todo;
		nr -= todo;
	}
}

/*
 * Lookup a swap entry in the swap cache. A found page will be returned
 * unlocked and with its refcount incremented - we rely on the kernel
 * lock getting page table operations atomic even if we drop the page
 * lock before returning.
 */
struct page * lookup_swap_cache(swp_entry_t entry)
{
	struct page *page;

	page = find_get_page(&swapper_space, entry.val);

	if (page)
		INC_CACHE_INFO(find_success);

	INC_CACHE_INFO(find_total);
	return page;
}

/* 
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 */
struct page *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	struct page *found_page, *new_page = NULL;
	int err;

	do {
		/*
		 * First check the swap cache.  Since this is normally
		 * called after lookup_swap_cache() failed, re-calling
		 * that would confuse statistics.
		 */
		found_page = find_get_page(&swapper_space, entry.val);
		if (found_page)
			break;

		/*
		 * Get a new page to read into from swap.
		 */
		if (!new_page) {
			new_page = alloc_page_vma(gfp_mask, vma, addr);
			if (!new_page)
				break;		/* Out of memory */
		}

		/*
		 * call radix_tree_preload() while we can wait.
		 */
		err = radix_tree_preload(gfp_mask & GFP_KERNEL);
		if (err)
			break;

		/*
		 * Swap entry may have been freed since our caller observed it.
		 */
		err = swapcache_prepare(entry);
		if (err == -EEXIST) {	/* seems racy */
			radix_tree_preload_end();
			continue;
		}
		if (err) {		/* swp entry is obsolete ? */
			radix_tree_preload_end();
			break;
		}

		/* May fail (-ENOMEM) if radix-tree node allocation failed. */
		__set_page_locked(new_page);
		SetPageSwapBacked(new_page);
		err = __add_to_swap_cache(new_page, entry);
		if (likely(!err)) {
			radix_tree_preload_end();
			/*
			 * Initiate read into locked page and return.
			 */
			lru_cache_add_anon(new_page);
			swap_readpage(new_page);
			return new_page;
		}
		radix_tree_preload_end();
		ClearPageSwapBacked(new_page);
		__clear_page_locked(new_page);
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		 */
		swapcache_free(entry, NULL);
	} while (err != -ENOMEM);

	if (new_page)
		page_cache_release(new_page);
	return found_page;
}

/**
 * swapin_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vma: user vma this address belongs to
 * @addr: target address for mempolicy
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...
 *
 * This has been extended to use the NUMA policies from the mm triggering
 * the readahead.
 *
 * Caller must hold down_read on the vma->vm_mm if vma is not NULL.
 */
struct page *swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	struct page *page;
	unsigned long offset = swp_offset(entry);
	unsigned long start_offset, end_offset;
	unsigned long mask = (1UL << page_cluster) - 1;

	/* Read a page_cluster sized and aligned cluster around offset. */
	start_offset = offset & ~mask;
	end_offset = offset | mask;
	if (!start_offset)	/* First page is swap header. */
		start_offset++;

	for (offset = start_offset; offset <= end_offset ; offset++) {
		/* Ok, do the async read-ahead now */
		page = read_swap_cache_async(swp_entry(swp_type(entry), offset),
						gfp_mask, vma, addr);
		if (!page)
			continue;
		page_cache_release(page);
	}
	lru_add_drain();	/* Push any new pages onto the LRU now */
	return read_swap_cache_async(entry, gfp_mask, vma, addr);
}
