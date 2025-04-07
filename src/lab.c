// src/lab.c
#include "lab.h"
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define handle_error_and_die(msg) \
    do { perror(msg); raise(SIGKILL); } while (0)

// Function to calculate the smallest power of 2 block size (kval) that can fit the requested size
size_t btok(size_t bytes) {
    if (bytes == 0) return MIN_K; // Return the smallest block size for zero-byte requests
    size_t k = MIN_K; // Start with the minimum block size
    size_t block_size = (1UL << k); // Calculate the block size as 2^k

    // Increment `k` until the block size is large enough to fit the requested bytes + metadata
    while (block_size < bytes + sizeof(struct avail)) {
        k++;
        block_size <<= 1; // Double the block size using bitwise left shift
    }
    fprintf(stderr, "btok: bytes=%zu, kval=%zu\n", bytes, k);
    return k;
}

// Function to calculate the buddy block's address using XOR
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block) {
    size_t offset = (char *)block - (char *)pool->base; // Calculate the offset of the block from the base
    size_t buddy_offset = offset ^ (1UL << block->kval); // XOR the offset with 2^kval to find the buddy's offset
    return (struct avail *)((char *)pool->base + buddy_offset); // Return the buddy's address
}

// Function to allocate memory from the buddy pool
void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (pool == NULL) {
        return NULL;
    }

    // Treat zero-byte requests as a request for the smallest block
    size_t totalSize = (size == 0) ? 1 : size + sizeof(struct avail); // Include metadata in the size
    size_t kval = btok(totalSize); // Get the smallest kval that fits the total size

    if (kval < SMALLEST_K) {
        kval = SMALLEST_K; // Enforce minimum block size
    }
    if (kval > pool->kval_m) {
        errno = ENOMEM; // Request exceeds pool size
        return NULL;
    }

    fprintf(stderr, "buddy_malloc: size=%zu, totalSize=%zu, kval=%zu\n", size, totalSize, kval);

    // Find the smallest available block that’s large enough
    size_t currentK = kval;
    struct avail *block = NULL;
    while (currentK <= pool->kval_m) {
        if (pool->avail[currentK].next != &pool->avail[currentK]) {
            block = pool->avail[currentK].next; // Found a block
            break;
        }
        currentK++;
    }

    if (block == NULL) {
        errno = ENOMEM; // No block found
        return NULL;
    }

    // Remove the block from its current list
    block->prev->next = block->next;
    block->next->prev = block->prev;

    // Split the block if it’s too large
    while (block->kval > kval) {
        block->kval--;
        size_t newSize = (1UL << block->kval);

        struct avail *buddy = (struct avail *)((char *)block + newSize);
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = block->kval;

        struct avail *list_head = &pool->avail[buddy->kval];
        buddy->next = list_head->next;
        buddy->prev = list_head;
        list_head->next->prev = buddy;
        list_head->next = buddy;
    }

    block->tag = BLOCK_RESERVED; // Mark the block as reserved

    // Debugging output
    fprintf(stderr, "buddy_malloc: Allocated block at %p with kval=%zu\n", block, (size_t)block->kval);

    return (void *)((char *)block + sizeof(struct avail)); // Return the memory block
}

// Function to free a previously allocated memory block
void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (ptr == NULL) return;

    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
    if (block->tag != BLOCK_RESERVED) return;

    block->tag = BLOCK_AVAIL;
    size_t current_k = block->kval;

    while (current_k < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);

        // Check if buddy is valid and available
        if ((char *)buddy >= (char *)pool->base + pool->numbytes ||
            buddy->tag != BLOCK_AVAIL || 
            buddy->kval != current_k) {
            break;
        }

        // Remove buddy from its list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Use the lower address as the new block
        block = (block < buddy) ? block : buddy;
        current_k++;
        block->kval = current_k;
    }

    // Add the block to its availability list
    struct avail *list_head = &pool->avail[current_k];
    block->next = list_head->next;
    block->prev = list_head;
    list_head->next->prev = block;
    list_head->next = block;

    // Debugging output
    fprintf(stderr, "buddy_free: Freed block at %p with kval=%zu\n", block, (size_t)block->kval);
}

// Function to initialize the buddy memory pool
void buddy_init(struct buddy_pool *pool, size_t size) {
    size_t kval = (size == 0) ? DEFAULT_K : btok(size);

    if (kval < MIN_K) kval = MIN_K;
    if (kval > MAX_K) kval = MAX_K - 1;

    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == pool->base) {
        handle_error_and_die("buddy_init mmap failed");
    }

    for (size_t i = 0; i <= kval; i++) {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    struct avail *block = (struct avail *)pool->base;
    block->tag = BLOCK_AVAIL;
    block->kval = kval;
    block->next = block->prev = &pool->avail[kval];
    pool->avail[kval].next = pool->avail[kval].prev = block;

    fprintf(stderr, "buddy_init: Initialized pool with base=%p, size=%zu\n", pool->base, pool->numbytes);
}

// Function to destroy the buddy memory pool
void buddy_destroy(struct buddy_pool *pool) {
    if (munmap(pool->base, pool->numbytes) == -1) // Unmap the memory pool
        handle_error_and_die("buddy_destroy munmap failed");
    memset(pool, 0, sizeof(struct buddy_pool)); // Clear the pool structure
}

