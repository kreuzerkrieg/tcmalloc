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

#include "tcmalloc/arena.h"

#include "tcmalloc/internal/logging.h"
#include "tcmalloc/system-alloc.h"
#include <sys/mman.h>

namespace tcmalloc {

void* Arena::Alloc(size_t bytes) {
    if (free_area_ == nullptr) {
        uint8_t *const base_address =
            reinterpret_cast<uint8_t *>(0x100000000000ULL);
        size_t size = 220'000'000'000;

        int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_HUGETLB;
        void *arena =
            mmap(base_address, size, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (arena == base_address) {
            free_area_ = reinterpret_cast<char *>(arena);
            free_avail_ = size;
        } else {
            std::string err_msg =
                "FATAL ERROR: Failed to open huge page memory. Reason: ";
            err_msg += std::strerror(errno);
            Crash(kCrash, __FILE__, __LINE__, err_msg.c_str(), kAllocIncrement, size,
                  arena);
        }
    }

  char* result;
  bytes = ((bytes + kAlignment - 1) / kAlignment) * kAlignment;
  if (free_avail_ < bytes) {
      Crash(kCrash, __FILE__, __LINE__,
            "FATAL ERROR: Out of memory trying to allocate internal tcmalloc "
            "data (bytes, object-size)",
            kAllocIncrement, bytes);
  }

  ASSERT(reinterpret_cast<uintptr_t>(free_area_) % kAlignment == 0);
  result = free_area_;
  free_area_ += bytes;
  free_avail_ -= bytes;
  bytes_allocated_ += bytes;
  return reinterpret_cast<void*>(result);
}

}  // namespace tcmalloc
