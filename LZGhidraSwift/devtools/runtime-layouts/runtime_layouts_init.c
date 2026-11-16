// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Constructor and accessor call for RuntimeLayouts.swift (see there).

#include <stddef.h>

typedef struct {
	const void *metadata;
	size_t state;
} MetadataResponse;

// A metadata accessor of a non-generic type takes the request in x0 (rdi) and returns the
// response in x0/x1 (rax/rdx); swiftcc and the C convention agree for this signature.
const void *runtime_layouts_call_accessor(const void *accessor) {
	return ((MetadataResponse(*)(size_t))accessor)(0).metadata;
}

extern void runtime_layouts_main(void);

__attribute__((constructor)) static void runtime_layouts_init(void) {
	runtime_layouts_main();
}
