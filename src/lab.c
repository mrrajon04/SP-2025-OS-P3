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
    size_t kval = MIN_K; // Start with the minimum block size
    size_t block_size = (1UL << kval); // Calculate the block size as 2^kval

    // Increment kval until the block size is large enough to fit the requested bytes + metadata
    while (block_size < bytes + sizeof(struct avail)) {
        kval++;
        block_size <<= 1; // Double the block size using bitwise left shift
    }
    return kval; // Return the kval corresponding to the required block size
}

// Function to calculate the buddy block's address using XOR
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block) {
    size_t offset = (char *)block - (char *)pool->base; // Calculate the offset of the block from the base
    size_t buddy_offset = offset ^ (1UL << block->kval); // XOR the offset with 2^kval to find the buddy's offset
    return (struct avail *)((char *)pool->base + buddy_offset); // Return the buddy's address
}

// Function to allocate memory from the buddy pool
void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    size_t kval = btok(size); // Calculate the required kval for the requested size

    // Search for a free block of sufficient size
    for (size_t k = kval; k <= pool->kval_m; k++) {
        if (pool->avail[k].next != &pool->avail[k]) { // Check if there is a free block in the current list
            struct avail *block = pool->avail[k].next; // Get the first free block

            // Remove the block from the free list
            block->prev->next = block->next;
            block->next->prev = block->prev;

            // Split the block into smaller blocks until the desired kval is reached
            while (k > kval) {
                k--;
                struct avail *buddy = (struct avail *)((char *)block + (1UL << k)); // Calculate the buddy's address
                buddy->kval = k; // Set the buddy's kval
                buddy->tag = BLOCK_AVAIL; // Mark the buddy as available

                // Add the buddy block to the free list
                buddy->next = pool->avail[k].next;
                buddy->prev = &pool->avail[k];
                pool->avail[k].next->prev = buddy;
                pool->avail[k].next = buddy;

                block->kval = k; // Update the block's kval
            }

            // Mark the block as reserved
            block->tag = BLOCK_RESERVED;

            // Return the memory block (excluding metadata)
            void *allocated_mem = (void *)(block + 1);
            if ((uintptr_t)allocated_mem % sizeof(void *) != 0) { // Ensure proper alignment
                fprintf(stderr, "Alignment error in buddy_malloc\n");
                errno = EINVAL;
                return NULL;
            }

            return allocated_mem; // Return the allocated memory
        }
    }

    // If no suitable block is found, set errno and return NULL
    errno = ENOMEM;
    return NULL;
}

// Function to free a previously allocated memory block
void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (!ptr) return; // Do nothing if the pointer is NULL

    struct avail *block = ((struct avail *)ptr) - 1; // Get the block's metadata
    block->tag = BLOCK_AVAIL; // Mark the block as available

    // Attempt to merge the block with its buddy
    while (block->kval < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block); // Calculate the buddy's address
        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval) break; // Stop if the buddy is not available or not the same size

        // Remove the buddy from the free list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Merge the blocks by updating the block's address and kval
        if (buddy < block) block = buddy;
        block->kval++;
    }

    // Add the merged block to the free list
    block->next = pool->avail[block->kval].next;
    block->prev = &pool->avail[block->kval];
    pool->avail[block->kval].next->prev = block;
    pool->avail[block->kval].next = block;
}

// Function to initialize the buddy memory pool
void buddy_init(struct buddy_pool *pool, size_t size) {
    size_t kval = (size == 0) ? DEFAULT_K : btok(size); // Determine the kval for the pool size
    if (kval < MIN_K) kval = MIN_K; // Ensure kval is at least MIN_K
    if (kval > MAX_K) kval = MAX_K - 1; // Ensure kval does not exceed MAX_K

    memset(pool, 0, sizeof(struct buddy_pool)); // Clear the pool structure
    pool->kval_m = kval; // Set the maximum kval for the pool
    pool->numbytes = (1UL << kval); // Calculate the total size of the pool

    // Allocate memory for the pool using mmap
    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->base == MAP_FAILED)
        handle_error_and_die("buddy_init mmap failed");

    // Initialize the free lists
    for (size_t i = 0; i <= kval; i++) {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i]; // Set up circular linked lists
        pool->avail[i].kval = i; // Set the kval for each list
        pool->avail[i].tag = BLOCK_UNUSED; // Mark the list as unused
    }

    // Initialize the first block to cover the entire pool
    struct avail *block = (struct avail *)pool->base;
    block->tag = BLOCK_AVAIL; // Mark the block as available
    block->kval = kval; // Set the block's kval
    block->next = block->prev = &pool->avail[kval]; // Add the block to the free list
    pool->avail[kval].next = pool->avail[kval].prev = block;

    // Debugging output to verify initialization
    fprintf(stderr, "buddy_init: Initialized pool with base=%p, size=%zu\n", pool->base, pool->numbytes);
}

// Function to destroy the buddy memory pool
void buddy_destroy(struct buddy_pool *pool) {
    if (munmap(pool->base, pool->numbytes) == -1) // Unmap the memory pool
        handle_error_and_die("buddy_destroy munmap failed");
    memset(pool, 0, sizeof(struct buddy_pool)); // Clear the pool structure
}

