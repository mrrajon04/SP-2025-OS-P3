// tests/test-lab.c
#include "harness/unity.h"
#include "../src/lab.h"
#include <errno.h>
#include <stdio.h>

void setUp(void) {}
void tearDown(void) {}

void check_buddy_pool_full(struct buddy_pool *pool) {
    for (size_t i = 0; i < pool->kval_m; i++) {
        TEST_ASSERT_EQUAL_PTR(pool->avail[i].next, &pool->avail[i]);
        TEST_ASSERT_EQUAL_PTR(pool->avail[i].prev, &pool->avail[i]);
        TEST_ASSERT_EQUAL(pool->avail[i].tag, BLOCK_UNUSED);
    }
    TEST_ASSERT_EQUAL(pool->avail[pool->kval_m].next->tag, BLOCK_AVAIL);
    TEST_ASSERT_EQUAL_PTR(pool->avail[pool->kval_m].next, pool->base);
}

void check_buddy_pool_empty(struct buddy_pool *pool) {
    for (size_t i = 0; i <= pool->kval_m; i++) {
        TEST_ASSERT_EQUAL_PTR(pool->avail[i].next, &pool->avail[i]);
        TEST_ASSERT_EQUAL_PTR(pool->avail[i].prev, &pool->avail[i]);
        TEST_ASSERT_EQUAL(pool->avail[i].tag, BLOCK_UNUSED);
    }
}

void test_buddy_init(void) {
    struct buddy_pool pool;
    for (size_t kval = MIN_K; kval <= DEFAULT_K; kval++) {
        buddy_init(&pool, (1UL << kval));
        check_buddy_pool_full(&pool);
        buddy_destroy(&pool);
    }
}

void test_buddy_malloc_and_free(void) {
    struct buddy_pool pool;
    buddy_init(&pool, (1UL << DEFAULT_K));
    void *mem = buddy_malloc(&pool, 100);
    TEST_ASSERT_NOT_NULL(mem);
    buddy_free(&pool, mem);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

void test_buddy_malloc_fail(void) {
    struct buddy_pool pool;
    buddy_init(&pool, (1UL << MIN_K));
    void *mem = buddy_malloc(&pool, (1UL << MIN_K));
    TEST_ASSERT_NOT_NULL(mem);
    void *fail_mem = buddy_malloc(&pool, 1);
    TEST_ASSERT_NULL(fail_mem);
    TEST_ASSERT_EQUAL(errno, ENOMEM);
    buddy_free(&pool, mem);
    buddy_destroy(&pool);
}

void test_multiple_allocations(void) {
    struct buddy_pool pool;
    buddy_init(&pool, (1UL << DEFAULT_K));

    void *mem1 = buddy_malloc(&pool, 128);
    void *mem2 = buddy_malloc(&pool, 256);
    void *mem3 = buddy_malloc(&pool, 512);

    TEST_ASSERT_NOT_NULL(mem1);
    TEST_ASSERT_NOT_NULL(mem2);
    TEST_ASSERT_NOT_NULL(mem3);

    buddy_free(&pool, mem2);
    buddy_free(&pool, mem1);
    buddy_free(&pool, mem3);

    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_buddy_init);
    RUN_TEST(test_buddy_malloc_and_free);
    RUN_TEST(test_buddy_malloc_fail);
    RUN_TEST(test_multiple_allocations);
    return UNITY_END();
}


