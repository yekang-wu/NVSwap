/*
 *  linux/mm/page_io.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, 
 *  Asynchronous swapping added 30.12.95. Stephen Tweedie
 *  Removed race in async swapping. 14.4.1996. Bruno Haible
 *  Add swap of shared pages through the page cache. 20.2.1998. Stephen Tweedie
 *  Always use brw_page, life becomes simpler. 12 May 1998 Eric Biederman
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <asm/pgtable.h>
#include <linux/swap.h>
#include <linux/syscalls.h>

#define NVM_SWAP_OUT_TIME_NS 2000

static struct bio *get_swap_bio(gfp_t gfp_flags,
				struct page *page, bio_end_io_t end_io)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, 1);
	if (bio) {
		bio->bi_sector = map_swap_page(page, &bio->bi_bdev);
		bio->bi_sector <<= PAGE_SHIFT - 9;
		bio->bi_io_vec[0].bv_page = page;
		bio->bi_io_vec[0].bv_len = PAGE_SIZE;
		bio->bi_io_vec[0].bv_offset = 0;
		bio->bi_vcnt = 1;
		bio->bi_idx = 0;
		bio->bi_size = PAGE_SIZE;
		bio->bi_end_io = end_io;
	}
	return bio;
}

static void end_swap_bio_write(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct page *page = bio->bi_io_vec[0].bv_page;

	if (!uptodate) {
		SetPageError(page);
		/*
		 * We failed to write the page out to swap-space.
		 * Re-dirty the page in order to avoid it being reclaimed.
		 * Also print a dire warning that things will go BAD (tm)
		 * very quickly.
		 *
		 * Also clear PG_reclaim to avoid rotate_reclaimable_page()
		 */
		set_page_dirty(page);
		printk(KERN_ALERT "Write-error on swap-device (%u:%u:%Lu)\n",
				imajor(bio->bi_bdev->bd_inode),
				iminor(bio->bi_bdev->bd_inode),
				(unsigned long long)bio->bi_sector);
		ClearPageReclaim(page);
	}
	end_page_writeback(page);
	bio_put(bio);

	// [wyk]
	if(swapOutRecord_status_end==1){
	   SwapOutRecord_AddEndT(page);
	}
}

void end_swap_bio_read(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct page *page = bio->bi_io_vec[0].bv_page;

	if (!uptodate) {
		SetPageError(page);
		ClearPageUptodate(page);
		printk(KERN_ALERT "Read-error on swap-device (%u:%u:%Lu)\n",
				imajor(bio->bi_bdev->bd_inode),
				iminor(bio->bi_bdev->bd_inode),
				(unsigned long long)bio->bi_sector);
	} else {
		SetPageUptodate(page);
	}
	unlock_page(page);
	bio_put(bio);

	// [wyk]
	if(swapInRecord_status_end==1){
		SwapInRecord_AddEndT(page);
	}
}

void mem_swap_writepage(struct page *page, struct swap_info_struct *si)
{
	swp_entry_t entry;
	pgoff_t offset, old;
	unsigned long pfn;
	void *pg_addr, *swp_addr;
	struct timespec txc_IO_startpoint, txc_IO_endpoint;
	s64 time_difference = 0;

	entry.val = page_private(page);
	old = swp_offset(entry);
	offset = si->slot_map[old];

	pfn = offset + si->start_pfn;
	swp_addr = __va(pfn << PAGE_SHIFT);
	
	getrawmonotonic(&txc_IO_startpoint);
	
	pg_addr = kmap_atomic(page);
	memcpy(swp_addr, pg_addr, PAGE_SIZE);
	kunmap_atomic(pg_addr);
	
	do {
		getrawmonotonic(&txc_IO_endpoint);
		time_difference = ((s64)txc_IO_endpoint.tv_sec*1000000000+txc_IO_endpoint.tv_nsec)-((s64)txc_IO_startpoint.tv_sec*1000000000+txc_IO_startpoint.tv_nsec);
		if(time_difference <= 0){
			printk(KERN_ALERT "[wyk][flag713][mem_swap_writepage] BUG: time measurement bug!\n");
			break;
		}
	} while (time_difference < NVM_SWAP_OUT_TIME_NS);
	
	// [wyk] Swap-out-end Record
	if(swapOutRecord_status_end==1){
		SwapOutRecord_AddEndT(page);
	}
}

/*
// another version: using x86 RDTSP to achieve the goal
void mem_swap_writepage(struct page *page, struct swap_info_struct *si)
{
	swp_entry_t entry;
	pgoff_t offset, old;
	unsigned long pfn;
	void *pg_addr, *swp_addr;
	u64 start, now;
	s64 differ_RDTSP_2us = 6000;

	entry.val = page_private(page);
	old = swp_offset(entry);
	offset = si->slot_map[old];

	pfn = offset + si->start_pfn;
	swp_addr = __va(pfn << PAGE_SHIFT);

	rdtscll(start);
	
	pg_addr = kmap_atomic(page);
	memcpy(swp_addr, pg_addr, PAGE_SIZE);
	kunmap_atomic(pg_addr);

	do {
		rep_nop();
		rdtscll(now);
	} while ((now - start) < differ_RDTSP_2us);
	
	// [wyk] Swap-out-end Record
	if(swapOutRecord_status_end==1){
		SwapOutRecord_AddEndT(page);
	}
}
*/

/*
 * We may have stale swap cache pages in memory: notice
 * them here and get rid of the unnecessary final write.
 */
int swap_writepage(struct page *page, struct writeback_control *wbc)
{
	struct bio *bio;
	int ret = 0, rw = WRITE;

	struct swap_info_struct *si = mem_swap_page2info(page);

	if (try_to_free_swap(page)) {
		unlock_page(page);
		goto out;
	}

	// [wyk] do memory swap
	if (si->flags & SWP_MEM) {
		count_vm_event(PSWPOUT);
		set_page_writeback(page);
		unlock_page(page);
		mem_swap_writepage(page, si);
		end_page_writeback(page);
		goto out;
	}

	bio = get_swap_bio(GFP_NOIO, page, end_swap_bio_write);
	if (bio == NULL) {
		set_page_dirty(page);
		unlock_page(page);
		ret = -ENOMEM;
		goto out;
	}
	if (wbc->sync_mode == WB_SYNC_ALL)
		rw |= REQ_SYNC;
	count_vm_event(PSWPOUT);
	set_page_writeback(page);
	unlock_page(page);
	submit_bio(rw, bio);
out:
	return ret;
}

void mem_swap_readpage(struct page *page, struct swap_info_struct *si)
{
	swp_entry_t entry;
	pgoff_t offset;
	unsigned long pfn;
	void *pg_addr, *swp_addr;

	entry.val = page_private(page);
	offset = swp_offset(entry);
	offset = si->slot_map[offset];

	pfn = offset + si->start_pfn;
	swp_addr = __va(pfn << PAGE_SHIFT);
	pg_addr = kmap_atomic(page);

	memcpy(pg_addr, swp_addr, PAGE_SIZE);

	kunmap_atomic(pg_addr);
}

int swap_readpage(struct page *page)
{
	struct bio *bio;
	int ret = 0;
	// [wyk] mem_swap
	struct swap_info_struct *si = mem_swap_page2info(page);

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(PageUptodate(page));

	if (si->flags & SWP_MEM) {
		count_vm_event(PSWPIN);
		mem_swap_readpage(page, si);
		unlock_page(page);
		SetPageUptodate(page);
		goto out;
	}

	bio = get_swap_bio(GFP_KERNEL, page, end_swap_bio_read);
	if (bio == NULL) {
		unlock_page(page);
		ret = -ENOMEM;
		goto out;
	}
	count_vm_event(PSWPIN);
	submit_bio(READ, bio);
out:
	return ret;
}
