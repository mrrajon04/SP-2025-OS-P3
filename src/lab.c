// Updated src/lab.c
#include "lab.h"
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);           \
    } while (0)

size_t btok(size_t bytes) {
    size_t kval = MIN_K;
    size_t block_size = (1UL << kval);
    while (block_size < bytes + sizeof(struct avail)) {
        kval++;
        block_size <<= 1;
    }
    return kval;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block) {
    size_t block_offset = (size_t)((char *)block - (char *)pool->base);
    size_t buddy_offset = block_offset ^ (1UL << block->kval);
    return (struct avail *)((char *)pool->base + buddy_offset);
}

void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    size_t kval = btok(size);
    for (size_t k = kval; k <= pool->kval_m; k++) {
        if (pool->avail[k].next != &pool->avail[k]) {
            struct avail *block = pool->avail[k].next;
            block->prev->next = block->next;
            block->next->prev = block->prev;
            while (k > kval) {
                k--;
                struct avail *buddy = (struct avail *)((char *)block + (1UL << k));
                buddy->kval = k;
                buddy->tag = BLOCK_AVAIL;
                buddy->next = buddy->prev = &pool->avail[k];
                pool->avail[k].next = pool->avail[k].prev = buddy;
                block->kval = k;
            }
            block->tag = BLOCK_RESERVED;
            return (void *)(block + 1);
        }
    }
    errno = ENOMEM;
    return NULL;
}

void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (!ptr) return;

    struct avail *block = ((struct avail *)ptr) - 1;
    block->tag = BLOCK_AVAIL;

    while (block->kval < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);
        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval) break;
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;
        if (buddy < block) block = buddy;
        block->kval++;
    }

    block->next = pool->avail[block->kval].next;
    block->prev = &pool->avail[block->kval];
    pool->avail[block->kval].next->prev = block;
    pool->avail[block->kval].next = block;
}

void buddy_init(struct buddy_pool *pool, size_t size) {
    size_t kval = (size == 0) ? DEFAULT_K : btok(size);
    if (kval < MIN_K) kval = MIN_K;
    if (kval > MAX_K) kval = MAX_K - 1;

    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (1UL << kval);

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->base == MAP_FAILED)
        handle_error_and_die("buddy_init mmap failed");

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
}

void buddy_destroy(struct buddy_pool *pool) {
    if (munmap(pool->base, pool->numbytes) == -1)
        handle_error_and_die("buddy_destroy munmap failed");
    memset(pool, 0, sizeof(struct buddy_pool));
}

