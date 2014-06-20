// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Internal implementation details for block.h. Not meant to be included
// directly.

#ifndef SYZYGY_AGENT_ASAN_BLOCK_IMPL_H_
#define SYZYGY_AGENT_ASAN_BLOCK_IMPL_H_

namespace agent {
namespace asan {

// Forward declaration.
struct BlockInfo;

// A structure describing the layout of a block. This is largely implementation
// detail, but exposed for unittesting. As far as the user is concerned this is
// an opaque blob.
struct BlockLayout {
  // The alignment of the entire block.
  size_t block_alignment;
  // The size of the entire block (the rest of the fields summed).
  size_t block_size;

  // Left redzone.
  size_t header_size;
  size_t header_padding_size;
  // Body.
  size_t body_size;
  // Right redzone.
  size_t trailer_padding_size;
  size_t trailer_size;
};

// Identifies whole pages that are spanned by the redzones and body of the
// given block. Directly sets the various *_pages* fields in @p block_info.
// @param block_info The block information to be inspected and modified.
// @note This is exposed as a convience function, but it is not meant to be
//     directly called by the user.
void BlockIdentifyWholePages(BlockInfo* block_info);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_BLOCK_IMPL_H_
