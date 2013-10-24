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
//
// Declares TypedBlock and ConstTypedBlock. These are thin wrappers to
// BlockGraph::Block objects which allow the data within a block to be
// interpreted as an object of a given type.
//
// Example use is as follows:
//
//   BlockGraph::Block* dos_header_block = ...;
//   TypedBlock<IMAGE_DOS_HEADER> dos_header;
//   DCHECK(dos_header.Init(0, dos_header_block));
//
//   // Reference the fields of the object as if we had a pointer to the object.
//   if (dos_header->e_magic == ...) ...
//
//   // Dereference pointers in the object using 'Dereference'. This takes care
//   // of finding, validating and following references within the block graph.
//   TypedBlock<IMAGE_NT_HEADERS> nt_headers;
//   DCHECK(dos_header.Dereference(dos_header->e_lfanew, &nt_headers));
//
// For full details of the API, refer to internal::TypedBlockImpl, defined in
// syzygy/block_graph/typed_block_internal.h

#ifndef SYZYGY_BLOCK_GRAPH_TYPED_BLOCK_H_
#define SYZYGY_BLOCK_GRAPH_TYPED_BLOCK_H_

#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

namespace internal {

typedef BlockGraph::Block* BlockPtr;
typedef const BlockGraph::Block* ConstBlockPtr;

// Forward declare.
template <typename T, typename BlockPtr, typename ChildType>
class TypedBlockImpl;

}  // namespace internal

// Used for interpreting a non-const BlockGraph::Block's data as a mutable
// object of type T. Augments TypedBlockImpl with routine's for modifying
// references.
template <typename T> class TypedBlock
    : public internal::TypedBlockImpl<T,
                                      internal::BlockPtr,
                                      TypedBlock<T>> {
 public:
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Reference Reference;
  typedef BlockGraph::ReferenceType ReferenceType;
  typedef BlockGraph::Size Size;
  typedef T ObjectType;

  template <typename T2> struct Rebind {
    typedef TypedBlock<typename T2> Type;
  };

  TypedBlock() : TypedBlockImpl() { }

  // Accesses the block encapsulated by this typed block.
  //
  // @returns a non-const pointer to the encapsulated block.
  internal::BlockPtr block() { return block_; }

  // Accesses the block encapsulated by this typed block.
  //
  // @returns a const pointer to the encapsulated block.
  internal::ConstBlockPtr block() const { return block_; }

  // Removes the reference at the given offset. Will clear a reference of any
  // size and type.
  //
  // @param offset the offset of the reference to clear.
  void RemoveReferenceAt(Offset offset) {
    RemoveReferenceImpl(offset, 0);
  }

  // Removes the reference at the given offset, but only if it has the given
  // size. Returns false if there exists a reference at the offset but with a
  // different size, true otherwise.
  //
  // @param offset the offset of the reference to clear.
  // @param size the size of the reference to clear.
  // @returns true on success, false otherwise.
  bool RemoveReferenceAt(Offset offset, size_t size) {
    return RemoveReferenceImpl(offset, size);
  }

  // Removes the reference corresponding to the given value. Succeeds if there
  // is no reference at the offset, or if the existing reference has the same
  // size as the value.
  //
  // @tparam TIn the type of @p value.
  // @param value the value in this block encapsulating the reference to erase.
  template <typename TIn>
  bool RemoveReference(const TIn& value) {
    return RemoveReferenceImpl(OffsetOf(value), sizeof(TIn));
  }

  // Builds a reference with the given type, offset and size to the given
  // block and offset.
  //
  // @param reference_type the type of reference to create.
  // @param reference_offset the offset of the reference to construct.
  // @param reference_size the size of the reference to construct.
  // @param referenced_block the block to be referenced.
  // @param referenced_offset the offset into the block to be directly
  //     referenced.
  // @param referenced_base the offset into the block of the item that is
  //     actually being referenced.
  // @returns true iff this inserts a new reference.
  bool SetReference(ReferenceType reference_type,
                    Offset reference_offset,
                    size_t reference_size,
                    Block* referenced_block,
                    Offset referenced_offset,
                    Offset referenced_base);

  // Sets a reference from one value to a given block/offset. The size of the
  // reference will be sizeof(TFrom).
  //
  // @tparam TFrom the type of @p value_from.
  // @param reference_type the type of reference to create.
  // @param value_from the value which will hold the created reference.
  // @param block_to the block to be referenced.
  // @param offset_to the offset of @p block_to to be referenced directly.
  // @param base_to the offset of @p block_to to be actually referenced.
  template <typename TFrom>
  bool SetReference(ReferenceType reference_type,
                    const TFrom& value_from,
                    Block* block_to,
                    Offset offset_to,
                    Offset base_to) {
    DCHECK(block_to != NULL);
    return SetReference(reference_type, OffsetOf(value_from), sizeof(TFrom),
        block_to, offset_to, base_to);
  }

  // Sets a direct reference (where base = offset) from one value to another
  // typed block. The size of the reference will be sizeof(TFrom).
  //
  // @tparam TFrom the type of @p value_from.
  // @tparam T2 the type encapsulated by @p typed_block_to.
  // @param reference_type the type of reference to create.
  // @param value_from the value which will hold the created reference.
  // @param typed_block_to the typed block that will be referenced. The
  //     reference will be constructed to the beginning of the object
  //     encapsulated by the typed block.
  // @returns true iff this inserts a new reference.
  template <typename TFrom, typename T2>
  bool SetReference(ReferenceType reference_type,
                    const TFrom& value_from,
                    const TypedBlock<T2>& typed_block_to) {
    return SetReference(reference_type, OffsetOf(value_from), sizeof(TFrom),
        const_cast<Block*>(typed_block_to.block()), typed_block_to.offset(),
                           typed_block_to.offset());
  }

  // Sets a direct reference (where base = offset) from one value to another.
  // The size of the reference will be sizeof(TFrom). The offset and base are
  // inferred from the position of @p value_to in @p typed_block_to.
  //
  // @tparam TFrom the type of @p value_from.
  // @tparam T2 the type encapsulated by @p typed_block_to.
  // @tparam TTo the type of value_to.
  // @param reference_type the type of reference to create.
  // @param value_from the value which will hold the created reference.
  // @param typed_block_to the typed block that will be referenced.
  // @param value_to the value within @p typed_block_to that will be referenced.
  // @returns true iff this inserts a new reference.
  template <typename TFrom, typename T2, typename TTo>
  bool SetReference(ReferenceType reference_type,
                    const TFrom& value_from,
                    const TypedBlock<T2>& typed_block_to,
                    const TTo& value_to) {
    Offset offset_to = typed_block_to.OffsetOf(value_to);
    return SetReference(reference_type, OffsetOf(value_from), sizeof(TFrom),
        const_cast<Block*>(typed_block_to.block()), offset_to, offset_to);
  }

 private:
  // Clears the reference at the given @p offset, but only if it has the given
  // @p size. If @p size = 0, then a reference of any size will be cleared.
  // Returns true on success, false otherwise.
  //
  // @param offset the offset of the reference to erase.
  // @param size the size of the reference to erase, 0 if it doesn't matter.
  bool RemoveReferenceImpl(Offset offset, size_t size);

  DISALLOW_COPY_AND_ASSIGN(TypedBlock);
};

// Used for interpreting a const BlockGraph::Block's data as a constant object
// of type T.
template <typename T> class ConstTypedBlock
    : public internal::TypedBlockImpl<const T,
                                      internal::ConstBlockPtr,
                                      ConstTypedBlock<T>> {
 public:
  typedef T ObjectType;

  template <typename T2> struct Rebind {
    typedef ConstTypedBlock<T2> Type;
  };

  ConstTypedBlock() : TypedBlockImpl() { }

  // Accesses the block encapsulated by this typed block.
  //
  // @returns a const pointer to the encapsulated block.
  internal::ConstBlockPtr block() const { return block_; }

 private:
  DISALLOW_COPY_AND_ASSIGN(ConstTypedBlock);
};

template <typename T>
bool TypedBlock<T>::SetReference(ReferenceType reference_type,
                                 Offset reference_offset,
                                 Size reference_size,
                                 Block* referenced_block,
                                 Offset referenced_offset,
                                 Offset referenced_base) {
  DCHECK(referenced_block != NULL);
  BlockGraph::Reference reference(reference_type, reference_size,
                                  referenced_block, referenced_offset,
                                  referenced_base);
  return block_->SetReference(reference_offset, reference);
}

template <typename T>
bool TypedBlock<T>::RemoveReferenceImpl(Offset offset, size_t size) {
  if (size != 0) {
    Reference reference;
    if (block_->GetReference(offset, &reference)) {
      if (reference.size() != size)
        return false;
    }
  }
  block_->RemoveReference(offset);
  return true;
}

}  // namespace block_graph

// This brings in the implementation.
#include "syzygy/block_graph/typed_block_internal.h"

#endif  // SYZYGY_BLOCK_GRAPH_TYPED_BLOCK_H_
