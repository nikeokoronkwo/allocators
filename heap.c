#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/// Log heap events and current memory ranges
static bool log_events = true;

/// printf, but can be globally disabled by setting `log_events` to false
static void log_event(const char* fmt) {
    if (log_events) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
    }
}

/// We will allocate memory from here
#define STORAGE_SIZE 4096;
static char storage[STORAGE_SIZE];

/// Denotes the edge, or *end* of our heap.
///
/// Once here, there is no free space to allocate.
static const char *storage_end = storage + STORAGE_SIZE;

/// The heap is divided into ranges, initially only 1 that covers the whole heap and is free.
typedef struct {
    uint64_t size: 63;
    bool allocated: 1;
} Header;

_Static_assert(sizeof(Header) == sizeof(uint64_t));

void log_header(Header header) {
    log_event("0x%016lx (%s, size = %u bytes)\n", header, header.allocated ? "allocated":"free", header.size);
}

static Header read_header(const char *ptr) { return *(Header *)ptr; }

static void write_header(char *ptr, Header header) {
  *(Header *)ptr = header;
  log_event("[%p] Set header to ", ptr);
  log_header(header);
}

/// Log the ranges currently in the heap.
static void log_ranges() {
  Header header = {.size = 0, .allocated = false};
  for (const char *header_ptr = storage; header_ptr < storage_end;
       header_ptr += header.size) {
    header = read_header(header_ptr);
    log_event("  [%p -> %p) : ", header_ptr, header_ptr + header.size);
    log_header(header);
  }
}

/// Search for a free range that has at least `bytes` of space
/// (callers should include the header size).
static char *find_free_space(size_t bytes) {
  Header header = {.size = 0, .allocated = false};
  for (char *header_ptr = storage; header_ptr < storage_end;
       header_ptr += header.size) {
    header = read_header(header_ptr);
    assert(header.size != 0 && "Header should always have non-zero size.");
    if (!header.allocated && (header.size >= bytes))
      return header_ptr;
  }

  return NULL;
}

void quak_heap_init() {
    log_event("Simple heap init:\n");
    log_event("Storage [%p -> %p) (%d bytes)\n", storage, storage_end, STORAGE_SIZE);
 
    // On startup, all the heap is one free range.
    Header hdr = {.size = STORAGE_SIZE, .allocated = false};
    write_header(storage, hdr);
    log_ranges();
}


void *quak_malloc(size_t size);
    
void quak_free(void *ptr);
