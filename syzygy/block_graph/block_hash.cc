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

#include "syzygy/block_graph/block_hash.h"

namespace block_graph {

using base::MD5Context;
using base::MD5Final;
using base::MD5Init;
using base::MD5Update;
using base::StringPiece;

void BlockHash::Hash(const BlockGraph::Block* block) {
  DCHECK(block != NULL);

  MD5Context md5_context;
  MD5Init(&md5_context);

  // Hash the block properties: type, size, data_size, reference count.
  BlockGraph::BlockType type = block->type();
  BlockGraph::Size size = block->size();
  BlockGraph::Size data_size = block->data_size();
  size_t reference_count = block->references().size();
  MD5Update(&md5_context,
      StringPiece(reinterpret_cast<const char*>(&type), sizeof(type)));
  MD5Update(&md5_context,
      StringPiece(reinterpret_cast<const char*>(&size), sizeof(size)));
  MD5Update(&md5_context,
      StringPiece(reinterpret_cast<const char*>(&data_size),
                  sizeof(data_size)));
  MD5Update(&md5_context,
      StringPiece(reinterpret_cast<const char*>(&reference_count),
                        sizeof(data_size)));

  // Hash the references in order of increasing source offset.
  BlockGraph::Block::ReferenceMap::const_iterator ref =
      block->references().begin();
  BlockGraph::Offset last_source_offset = -1;
  for (; ref != block->references().end(); ++ref) {
    CHECK_LT(last_source_offset, ref->first);
    last_source_offset = ref->first;

    // Hash the reference: source offset, type, size.
    BlockGraph::Offset offset = ref->first;
    BlockGraph::ReferenceType type = ref->second.type();
    BlockGraph::Size size = ref->second.size();
    MD5Update(&md5_context,
        StringPiece(reinterpret_cast<const char*>(&offset), sizeof(offset)));
    MD5Update(&md5_context,
        StringPiece(reinterpret_cast<const char*>(&type), sizeof(type)));
    MD5Update(&md5_context,
        StringPiece(reinterpret_cast<const char*>(&size), sizeof(size)));
  }

  // Hash the data, skipping locations of references.
  size_t data_index = 0;
  ref = block->references().begin();
  for (; ref != block->references().end(); ++ref) {
    DCHECK_LE(0, ref->first);
    size_t ref_offset = static_cast<size_t>(ref->first);

    // Have data to hash before this reference?
    if (data_index < block->data_size() && data_index < ref_offset) {
      size_t data_end = block->data_size();
      if (ref_offset < data_end)
        data_end = ref_offset;

      MD5Update(&md5_context,
          StringPiece(reinterpret_cast<const char*>(
              block->data() + data_index), data_end - data_index));
    }

    // Skip past this reference.
    data_index = ref_offset + ref->second.size();
  }

  // Hash any data after the last reference.
  if (data_index < block->data_size()) {
    MD5Update(&md5_context,
        StringPiece(reinterpret_cast<const char*>(
            block->data() + data_index), block->data_size() - data_index));
    data_index = block->data_size();
  }

  // Hash any trailing zero bytes in the block. The zeros are implied if the
  // data size is less than the block size.
  while (data_index < block->size()) {
    static const char kZeros[32] = { 0 };
    size_t bytes = block->size() - data_index;
    if (bytes > sizeof(kZeros))
      bytes = sizeof(kZeros);
    MD5Update(&md5_context, StringPiece(kZeros, bytes));
    data_index += bytes;
  }

  // Finalize the hash.
  MD5Final(&md5_digest, &md5_context);
}

}  // namespace block_graph
