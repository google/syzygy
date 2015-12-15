// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/experimental/compare/block_compare.h"

namespace experimental {

// A utility function for comparing values.
template<typename T> int CompareValues(const T t1, const T t2) {
  if (t1 < t2)
    return -1;
  if (t1 > t2)
    return 1;
  return 0;
}

// Compares two references. This uses the same semantics as that used by the
// BlockHash function.
int CompareReferences(const BlockGraph::Reference& ref1,
                      const BlockGraph::Reference& ref2) {
  int c = 0;
  if ((c = CompareValues(ref1.type(), ref2.type())) != 0)
    return c;
  return CompareValues(ref1.size(), ref2.size());
}

// We assume that BlockGraph::Offset is a signed quantity. This ensures that
// an error will be thrown if this is not the case. This assumption is made
// in CompareBlocks and BlockHash::Hash, with the value last_source_offset.
static_assert(static_cast<BlockGraph::Offset>(-1) < 0,
              "BlockGraph offset must be signed.");

// Compares two blocks. This uses the same semantics as that used by the
// BlockHash function, allowing us to use it to detect hash collisions.
int BlockCompare(const BlockGraph::Block* block0,
                 const BlockGraph::Block* block1) {
  DCHECK(block0 != NULL);
  DCHECK(block1 != NULL);

  // Compare basic block properties: type, size, data_size, reference count.
  int c = 0;
  if ((c = CompareValues(block0->type(), block1->type())) != 0)
    return c;
  if ((c = CompareValues(block0->size(), block1->size())) != 0)
    return c;
  if ((c = CompareValues(block0->data_size(), block1->data_size())) != 0)
    return c;
  c = CompareValues(block0->references().size(),
                    block1->references().size());
  if (c != 0)
    return c;

  // Compare the references. We assume that they are stored in order of
  // increasing source offset.
  BlockGraph::Block::ReferenceMap::const_iterator ref1 =
    block0->references().begin();
  BlockGraph::Block::ReferenceMap::const_iterator ref2 =
    block1->references().begin();
  BlockGraph::Offset last_source_offset = -1;
  for (; ref1 != block0->references().end(); ++ref1, ++ref2) {
    // Ensure source offsets are strictly increasing!
    CHECK_LT(last_source_offset, ref1->first);
    last_source_offset = ref1->first;

    // Compare the source offsets.
    if ((c = CompareValues(ref1->first, ref2->first)) != 0)
      return c;

    // Compare the references themselves (type and size).
    if ((c = CompareReferences(ref1->second, ref2->second)) != 0)
      return c;
  }

  // Compare the data, skipping locations of references.
  size_t data_index = 0;
  ref1 = block0->references().begin();
  for (; ref1 != block0->references().end(); ++ref1) {
    DCHECK_LE(0, ref1->first);
    size_t ref_offset = static_cast<size_t>(ref1->first);

    // Have data to hash before this reference?
    if (data_index < block0->data_size() && data_index < ref_offset) {
      size_t data_end = block0->data_size();
      if (ref_offset < data_end)
        data_end = ref_offset;

      c = memcmp(block0->data() + data_index,
                 block1->data() + data_index,
                 data_end - data_index);
      if (c != 0)
        return c;
    }

    // Skip past this reference.
    data_index = ref_offset + ref1->second.size();
  }

  // Compare any data after the last reference.
  if (data_index < block0->data_size()) {
    c = memcmp(block0->data() + data_index,
               block1->data() + data_index,
               block0->data_size() - data_index);
    if (c != 0)
      return c;
  }

  // We don't need to compare bytes [data_size, size), as these are always
  // implicitly zero and thus equal.

  return 0;
}

}  // namespace experimental
