// Copyright 2017 Google Inc. All Rights Reserved.
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
// This transform injects (creates or inserts) an implicit TLS slot
// inside a PE image. An implicit TLS slot is what the MSVC-specific
// __declspec(thread) extension uses. Long story short, when a
// variable is declared with this, both the compiler and linker
// work to allocate storage for the variable. The way they achieve this
// is documented in the following link: http://www.nynaeve.net/?p=183.
//
// An implicit TLS slot has the same goal as an explicit
// (Tls[Get/Set]Value) TLS slot: providing a per-thread area for
// storing information.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ADD_IMPLICIT_TLS_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ADD_IMPLICIT_TLS_TRANSFORM_H_

#include "base/logging.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace instrument {
namespace transforms {

typedef block_graph::BlockGraph BlockGraph;
typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

class AddImplicitTlsTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          AddImplicitTlsTransform> {
 public:
  AddImplicitTlsTransform(BlockGraph::Block* tls_index_data_block,
                          size_t tls_index_offset)
      : tls_index_data_block_(tls_index_data_block),
        tls_index_offset_(tls_index_offset) {}

  static const char kTransformName[];
  static const char kTlsIndex[];
  static const char kTlsUsed[];
  static const char kTlsSectionName[];

  bool TransformBlockGraph(const TransformPolicyInterface* policy,
                           BlockGraph* block_graph,
                           BlockGraph::Block* header_block) final;

  // This is the displacement offset of where the TLS variable is placed at in
  // the memory that will get allocated by the PE loader.
  // This displacement is used to access the storage address for the slot:
  //   SlotAddress = TEB.ThreadLocalStoragePointer[TlsIndex] + Displacement
  // This value is only valid once TransformBlockGraph has been called.
  const size_t tls_displacement() const { return tls_displacement_; }

 protected:
  // Create an implicit TLS slot. This implies injecting a new section where
  // the TLS slot is stored, injecting IMAGE_TLS_DIRECTORY metadata in the
  // .rdata section and modifying the ImageDirectory for TLS in the NT headers.
  bool CreateImplicitTlsSlot(BlockGraph* block_graph,
                             BlockGraph::Block* header_block);

  // Insert an implicit TLS slot. This function is called only if implicit
  // slots are already present. In this case, it extends the TLS storage
  // (at the end of it) to accomodate an extra slot.
  bool InsertImplicitTlsSlot(BlockGraph* block_graph);

  // This is the data block we redirect TlsIndex into.
  // It is useful as the caller can redirect it into a block
  // of its choosing.
  BlockGraph::Block* tls_index_data_block_;

  // This is the offset (relative to the above block) at which
  // TlsIndex is placed.
  size_t tls_index_offset_;

  // This is the displacement offset of where the TLS variable is placed at.
  size_t tls_displacement_;
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ADD_IMPLICIT_TLS_TRANSFORM_H_
