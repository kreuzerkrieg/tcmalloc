// Copyright 2019 The TCMalloc Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tcmalloc/static_vars.h"

#include <stddef.h>

#include <atomic>
#include <new>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "absl/base/attributes.h"
#include "absl/base/const_init.h"
#include "absl/base/internal/spinlock.h"
#include "absl/base/macros.h"
#include "tcmalloc/cpu_cache.h"
#include "tcmalloc/internal/logging.h"
#include "tcmalloc/internal/mincore.h"
#include "tcmalloc/malloc_extension.h"
#include "tcmalloc/pagemap.h"
#include "tcmalloc/sampler.h"
#include "tcmalloc/thread_cache.h"
#include "tcmalloc/tracking.h"

static std::tuple<uint8_t*, size_t> getHugeMem()
{
    size_t total_hugepages = 0;
    size_t free_hugepages = 0;
    {
        char buf[512] = {'\0'};
        auto fd = open("/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages", O_RDONLY);
        auto len = read(fd, buf, 512);
        close(fd);
        total_hugepages = std::atoi(buf);
        if (total_hugepages == 0)
        {
            ::tcmalloc::Crash(::tcmalloc::kCrash, __FILE__, __LINE__, "No 1GiB hugepages are available");
        }
    }
    {
        char buf[512] = {'\0'};
        auto fd = open("/sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages", O_RDONLY);
        auto len = read(fd, buf, 512);
        close(fd);
        free_hugepages = std::atoi(buf);
        if (free_hugepages == 0)
        {
            ::tcmalloc::Crash(::tcmalloc::kCrash, __FILE__, __LINE__, "No free 1GiB hugepages are available");
        }
    }

    uint8_t *const base_address =
        reinterpret_cast<uint8_t *>(0x40000000000ULL);
    size_t size = free_hugepages * 1024 * 1024 * 1024;

    int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_HUGETLB;
    void *arena =
        mmap(base_address, size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (arena == base_address) {
        return {reinterpret_cast<uint8_t*>(arena),size};
    } else {
        // TODO: Add some human readable message why mmap failed
        ::tcmalloc::Crash(::tcmalloc::kCrash, __FILE__, __LINE__, "Failed to `mmap` hugepages", size);
    }
}
namespace tcmalloc {

// Cacheline-align our SizeMap and CPUCache.  They both have very hot arrays as
// their first member variables, and aligning them reduces the number of cache
// lines these arrays use.
//
// IF YOU ADD TO THIS LIST, ADD TO STATIC_VAR_SIZE TOO!
ABSL_CONST_INIT absl::base_internal::SpinLock pageheap_lock(
    absl::kConstInit, absl::base_internal::SCHEDULE_KERNEL_ONLY);
ABSL_CONST_INIT Arena Static::arena_;
SizeMap ABSL_CACHELINE_ALIGNED Static::sizemap_;
ABSL_CONST_INIT TransferCacheManager Static::transfer_cache_;
CPUCache ABSL_CACHELINE_ALIGNED Static::cpu_cache_;
PageHeapAllocator<Span> Static::span_allocator_;
PageHeapAllocator<StackTrace> Static::stacktrace_allocator_;
PageHeapAllocator<ThreadCache> Static::threadcache_allocator_;
ABSL_CONST_INIT SpanList Static::sampled_objects_;
ABSL_CONST_INIT tcmalloc_internal::StatsCounter Static::sampled_objects_size_;
ABSL_CONST_INIT PeakHeapTracker Static::peak_heap_tracker_;
PageHeapAllocator<StackTraceTable::Bucket> Static::bucket_allocator_;
ABSL_CONST_INIT std::atomic<bool> Static::inited_{false};
bool Static::cpu_cache_active_;
Static::PageAllocatorStorage Static::page_allocator_;
PageMap Static::pagemap_;
ABSL_CONST_INIT absl::base_internal::SpinLock guarded_page_lock(
    absl::kConstInit, absl::base_internal::SCHEDULE_KERNEL_ONLY);
ABSL_CONST_INIT GuardedPageAllocator Static::guardedpage_allocator_;

size_t Static::metadata_bytes() {
  // This is ugly and doesn't nicely account for e.g. alignment losses
  // -- I'd like to put all the above in a struct and take that
  // struct's size.  But we can't due to linking issues.
  const size_t static_var_size =
      sizeof(pageheap_lock) + sizeof(arena_) + sizeof(sizemap_) +
      sizeof(transfer_cache_) + sizeof(cpu_cache_) + sizeof(span_allocator_) +
      sizeof(stacktrace_allocator_) + sizeof(threadcache_allocator_) +
      sizeof(sampled_objects_) + sizeof(bucket_allocator_) +
      sizeof(inited_) + sizeof(cpu_cache_active_) + sizeof(page_allocator_) +
      sizeof(pagemap_) + sizeof(sampled_objects_size_) +
      sizeof(peak_heap_tracker_) + sizeof(guarded_page_lock) +
      sizeof(guardedpage_allocator_);

  const size_t allocated = arena()->bytes_allocated() +
                           AddressRegionFactory::InternalBytesAllocated();
  return allocated + static_var_size;
}

size_t Static::pagemap_residence() {
  // Determine residence of the root node of the pagemap.
  size_t total = MInCore::residence(&pagemap_, sizeof(pagemap_));
  return total;
}

ABSL_ATTRIBUTE_COLD ABSL_ATTRIBUTE_NOINLINE void Static::SlowInitIfNecessary() {
  absl::base_internal::SpinLockHolder h(&pageheap_lock);

  // double-checked locking
  if (!inited_.load(std::memory_order_acquire)) {
    auto&& [huge_address, huge_size] = getHugeMem();
    current_ptr_ = base_ptr_ = huge_address;
    hugemem_size_ = huge_size;

    tracking::Init();
    sizemap_.Init();
    span_allocator_.Init(&arena_);
    span_allocator_.New();  // Reduce cache conflicts
    span_allocator_.New();  // Reduce cache conflicts
    stacktrace_allocator_.Init(&arena_);
    bucket_allocator_.Init(&arena_);
    // Do a bit of sanitizing: make sure central_cache is aligned properly
    CHECK_CONDITION((sizeof(transfer_cache_) % ABSL_CACHELINE_SIZE) == 0);
    transfer_cache_.Init();
    new (page_allocator_.memory) PageAllocator;
    threadcache_allocator_.Init(&arena_);
    cpu_cache_active_ = false;
    pagemap_.MapRootWithSmallPages();
    guardedpage_allocator_.Init(/*max_alloced_pages=*/64, /*total_pages=*/128);
    inited_.store(true, std::memory_order_release);
  }
}

}  // namespace tcmalloc
