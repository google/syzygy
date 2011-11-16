// Copyright 2011 Google Inc.
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
// object of type T.
template <typename T> class TypedBlock
    : public internal::TypedBlockImpl<T,
                                      internal::BlockPtr,
                                      TypedBlock<T>> {
 public:
  template <typename T2> struct Rebind {
    typedef TypedBlock<T2> Type;
  };

  TypedBlock() : TypedBlockImpl() { }

 private:
  DISALLOW_COPY_AND_ASSIGN(TypedBlock);
};

// Used for interpreting a const BlockGraph::Block's data as a constant object
// of type T.
template <typename T> class ConstTypedBlock
    : public internal::TypedBlockImpl<const T,
                                      internal::ConstBlockPtr,
                                      ConstTypedBlock<T>> {
 public:
  template <typename T2> struct Rebind {
    typedef ConstTypedBlock<T2> Type;
  };

  ConstTypedBlock() : TypedBlockImpl() { }

 private:
  DISALLOW_COPY_AND_ASSIGN(ConstTypedBlock);
};

}  // namespace block_graph

// This brings in the implementation.
#include "syzygy/block_graph/typed_block_internal.h"

#endif  // SYZYGY_BLOCK_GRAPH_TYPED_BLOCK_H_
