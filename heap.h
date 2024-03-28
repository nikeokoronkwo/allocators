// Copyright (C) 2024 Nikechukwu Okoronkwo
// This file is governed by the license found in the LICENSE file of this repository
#include <stddef.h>

/// Initialise the heap
/// 
/// This function is to be called once at the start of main() to initialise the empty heap.
/// This is the equivalent of what your C library is doing before main() system heap.
void quak_heap_init();

/// Allocate memory from the heap of size `size` and return a pointer to that memory
void *quak_malloc(size_t size);

/// Free memory from the heap referenced by `ptr`
void quak_free(void *ptr);
