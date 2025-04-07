// src/lab.c
#include "lab.h"
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

#define handle_error_and_die(msg) \
    do { perror(msg); raise(SIGKILL); } while (0)

// Function to calculate the smallest power of 2 block size (kval) that can fit the requested size
size_t btok(size_t bytes) {
    int kval = 0;
    // Find the smallest power k such that 2^k is greater than or equal to bytes.
    while ((UINT64_C(1) << kval) < (uint64_t)bytes) {
        kval++;
    }
    return (size_t)kval;
}

// Function to calculate the buddy block's address using XOR
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block) {
    if (!pool || !block) {
        errno = ENOMEM;
        return NULL;
    }

    uintptr_t base_addr = (uintptr_t)pool->base;
    uintptr_t block_addr = (uintptr_t)block;
    size_t block_size = (UINT64_C(1) << block->kval);

    uintptr_t buddy_offset = (block_addr - base_addr) ^ block_size;
    uintptr_t buddy_addr = base_addr + buddy_offset;

    return (struct avail *)buddy_addr;
}

// Function to allocate memory from the buddy pool
void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (pool == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    // Treat zero-byte requests as a request for the smallest block
    size_t totalSize = (size == 0) ? 1 : size + sizeof(struct avail); // Include metadata in the size
    size_t kval = btok(totalSize); // Get the smallest kval that fits the total size

    // Enforce a minimum block size only if the pool is large enough
    if (kval < SMALLEST_K && pool->kval_m >= SMALLEST_K) {
        kval = SMALLEST_K;
    }

    if (kval > pool->kval_m) {
        errno = ENOMEM; // Request exceeds pool size
        return NULL;
    }

    size_t j = kval;
    bool block_found = false;

    // Search for a free block starting at order 'kval' up to the maximum order
    while (j <= pool->kval_m) {
        if (pool->avail[j].next != &pool->avail[j]) {
            block_found = true;
            break;
        }
        j++;
    }

    if (!block_found) {
        errno = ENOMEM;
        return NULL;
    }

    // Remove the block from the free list
    struct avail *block = pool->avail[j].next;
    block->prev->next = block->next;
    block->next->prev = block->prev;

    // Split the block until we reach the desired order
    while (j > kval) {
        j--;
        uintptr_t addr = (uintptr_t)block;
        uintptr_t buddy_addr = addr + (UINT64_C(1) << j);
        struct avail *buddy = (struct avail *)buddy_addr;

        buddy->tag = BLOCK_AVAIL;
        buddy->kval = j;

        // Insert buddy into the free list for order j
        buddy->next = pool->avail[j].next;
        buddy->prev = &pool->avail[j];
        pool->avail[j].next->prev = buddy;
        pool->avail[j].next = buddy;

        // Update the current block's order
        block->kval = j;
    }

    block->tag = BLOCK_RESERVED;

    // Return a pointer to the usable memory (after the metadata header)
    return (void *)(block + 1);
}

// Function to free a previously allocated memory block
void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (!pool || !ptr)
        return;

    // Adjust pointer back to the metadata header.
    struct avail *block = (struct avail *)ptr - 1;
    size_t kval = block->kval;

    // Mark block as free.
    block->tag = BLOCK_AVAIL;

    // Attempt to merge with buddy as long as we haven't reached the maximum order.
    while (kval < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);

        // If buddy_calc returns the same block or the buddy isn't free at the same order, stop merging.
        if (buddy == block || !(buddy->tag == BLOCK_AVAIL && buddy->kval == kval))
            break;

        // Remove buddy from its free list.
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Use the lower address between the block and its buddy.
        if ((uintptr_t)buddy < (uintptr_t)block)
            block = buddy;

        kval++;
        block->kval = kval;
    }

    // Reinsert the (possibly merged) block into the free list.
    block->prev = &pool->avail[kval];
    block->next = pool->avail[kval].next;
    pool->avail[kval].next->prev = block;
    pool->avail[kval].next = block;
}

// Function to initialize the buddy memory pool
void buddy_init(struct buddy_pool *pool, size_t size) {
    size_t kval = size == 0 ? DEFAULT_K : btok(size);
    if (kval < MIN_K) kval = MIN_K;
    if (kval > MAX_K) kval = MAX_K - 1;

    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == pool->base) {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    // Initialize free list
    for (size_t i = 0; i <= kval; i++) {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

// Function to destroy the buddy memory pool
void buddy_destroy(struct buddy_pool *pool) {
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval) {
        handle_error_and_die("buddy_destroy avail array");
    }
    memset(pool, 0, sizeof(struct buddy_pool));
}


