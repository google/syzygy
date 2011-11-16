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
// Internal implementation details of TypedBlock. Not to be included directly.

#ifndef SYZYGY_BLOCK_GRAPH_TYPED_BLOCK_INTERNAL_H_
#define SYZYGY_BLOCK_GRAPH_TYPED_BLOCK_INTERNAL_H_

namespace block_graph {

namespace internal {

// Overloaded function that calls the appropriate block data accessor depending
// on whether or not the block is const.
inline uint8* GetBlockData(BlockPtr block) {
  DCHECK(block != NULL);
  return block->GetMutableData();
}
inline const uint8* GetBlockData(ConstBlockPtr block) {
  DCHECK(block != NULL);
  return block->data();
}

// A TypedBlockImpl is a simple wrapper to a BlockGraph::Block that lets its
// data be interpreted directly as a data structure of the given templated type,
// all while observing const correctness.
//
// Care should be taken *not* to follow pointers in these objects directly, but
// rather to follow them using the 'Dereference' member function.
//
// This class is not meant to be used directly, but rather acts as a back-end
// for TypedBlock and ConstTypedBlock, both of which fully specify BlockPtr
// and ChildType.
//
// @tparam T the type of object that this typed block encapsulates.
// @tparam BlockPtr the type of pointer to BlockGraph::Block that this object
//     stores. If this is const, T must also be const for const-correctness.
// @tparam ChildType the type of the derived class that inherits from this
//     class. This is necessary so that the API can accept pointers to this
//     type.
template <typename T, typename BlockPtr, typename ChildType>
class TypedBlockImpl {
 public:
  typedef T ObjectType;

  // A struct that allows us to get the ChildType rebound with another
  // encapsulated data type.
  //
  // @tparam T2 the new encapsulated type.
  template <typename T2> struct ReboundChild {
    typedef typename ChildType::Rebind<T2>::Type Type;
  };

  // Default constructor.
  TypedBlockImpl() : offset_(0), block_(NULL), size_(0) {
  }

  // Initializes this typed block with the given @p block and @p offset.
  //
  // @param offset the offset in to @p block to interpret as type T.
  // @param block the block with data to interpret as type T.
  // @returns true if the typed block is valid, false otherwise.
  bool Init(BlockGraph::Offset offset, BlockPtr block) {
    return InitWithSize(offset, sizeof(T), block);
  }

  // Initializes this typed block with the given @p offset, @p block and
  // @p size. This is useful for interpreting arrays and types that concatenate
  // tail arrays.
  //
  // @param size the size of the data in block we want to cover.
  // @param offset the offset in to @p block to interpret as type T.
  // @param block the block with data to interpret as type T.
  // @pre @p size >= sizeof(T).
  // @returns true if the typed block is valid, false otherwise.
  bool InitWithSize(BlockGraph::Offset offset, size_t size, BlockPtr block) {
    DCHECK_LE(sizeof(T), size);
    if (block == NULL || block->data_size() < offset + size)
      return false;

    offset_ = offset;
    block_ = block;
    size_ = size;
    return true;
  }

  // Accesses the block encapsulated by this typed block.
  //
  // @returns a pointer to the encapsulated block.
  BlockPtr block() { return block_; }

  // Accesses the offset into the block used by this typed block.
  //
  // @returns the offset of the encapsulated object.
  BlockGraph::Offset offset() { return offset_; }

  // Determines if this typed block refers to a valid region of block data.
  //
  // @returns true if derefencing will succeed, false otherwise.
  bool IsValid() const {
    return IsValidElement(0);
  }

  // Determines if element @p elem of typed block refers to a valid
  // region of block data.
  //
  // @returns true if derefencing @p elem will succeed, false otherwise.
  bool IsValidElement(size_t elem) const {
    return InBlock(sizeof(T) * elem, sizeof(T));
  }

  // Dereferences this object, returning a pointer to it.
  //
  // @returns a pointer to the dereferenced object.
  // @pre IsValid() == true.
  T* Get() const { return GetImpl(0); }

  // Operators for dereferencing the object.
  // @{
  T* operator->() const { return GetImpl(0); }
  T& operator*() const { return *GetImpl(0); }
  T& operator[](size_t i) const { return *GetImpl(i); }
  // @}

  // Follows a reference at a given @p offset in the enclosed structure.
  //
  // @tparam ReboundChildType another type of ChildType, but with another
  //     encapsulated object type.
  // @param offset the offset into this object. This must be within the object.
  // @param typed_block the typed block to receive the dereferenced block. It
  //     may or may not be valid.
  // @returns true if the dereference was successful, false otherwise.
  template <typename ReboundChildType>
  bool DereferenceAt(BlockGraph::Offset offset,
                     ReboundChildType* typed_block) const {
    typedef typename ReboundChildType::ObjectType T2;
    return DereferenceImpl<T2>(offset_ + offset, 0, typed_block);
  }

  // Dereferences a value in the enclosed structure.
  //
  // @tparam ReboundChildType another type of ChildType, but with another
  //     encapsulated object type.
  // @tparam TIn the type of the input @p value.
  // @param value a reference to the value to dereference. This must be within
  //     the object.
  // @param typed_block the typed block to receive the dereferenced block. It
  //     may or may not be valid.
  // @returns true if the dereference was successful, false otherwise.
  template <typename ReboundChildType, typename TIn>
  bool Dereference(TIn& value,
                   ReboundChildType* typed_block) const {
    BlockGraph::Offset offset = OffsetOf(value);

    typedef typename ReboundChildType::ObjectType T2;
    return DereferenceImpl<T2>(offset, sizeof(TIn), typed_block);
  }

  // Compute the offset of a field in the enclosed structure.
  //
  // @tparam TIn the type of the input @p value.
  // @param value a reference to the value to dereference. This must be within
  //     the object.
  // @returns the offset of value within the the referenced block.
  template <typename TIn>
  BlockGraph::Offset OffsetOf(TIn& value) const {
    const uint8* value_address = reinterpret_cast<const uint8*>(&value);
    BlockGraph::Offset offs = value_address - block_->data();
    DCHECK(InBlock(offs, sizeof(value)));
    return offs;
  }

 protected:
  // Determines whether the byte range starting at @p offset and extending for
  // @p size bytes is in the data covered by the block.
  //
  // @returns true if the block covers the byte range @p offset and @p size,
  //     false otherwise.
  bool InBlock(size_t offset, size_t size) const {
    return block_ != NULL && (offset_ + offset) >= 0 &&
        block_->data_size() >= (offset_ + offset + size);
  }

  // Interprets the underlying data as an array of type T, returning a
  // pointer to element @p elem of it. If the pointer is mutable and
  // the block doesn't own its data, causes it to be copied so that local
  // changes are possible.
  // It is an error to call this unless the block has data to cover @p elem.
  //
  // @param elem the index of the element to dereference
  // @pre IsValidElement(elem) returns true.
  // @returns a typed pointer to the encapsulated object.
  T* GetImpl(size_t elem) const {
    DCHECK(IsValidElement(elem));
    // If you get an error referring you to this line, you're likely not
    // const correct!
    return reinterpret_cast<T*>(
        internal::GetBlockData(block_) + offset_) + elem;
  }

  // Attempts to follow a reference of given @p size at the given @p offset
  // into the block. This only succeeds if their is a reference at the given
  // offset, it matches the given size, is contained entirely within the
  // object encapsulated by this typed block, and the referenced block is
  // sufficiently large to represent an object of type T2.
  //
  // @tparam T2 the type encapsulated by @p typed_block.
  // @param offset the offset into the block.
  // @param size the expected size of the reference. If this is 0, a reference
  //     of any size is accepted.
  // @param typed_block the typed block that will represent the dereferenced
  //     object.
  // @returns true on success, false otherwise.
  template <typename T2>
  bool DereferenceImpl(
      BlockGraph::Offset offset,
      size_t size,
      typename ReboundChild<T2>::Type* typed_block) const {
    DCHECK(typed_block != NULL);

    // Ensure that we are in the bounds of the encapsulated object.
    if (offset < offset_ || offset + size > offset_ + size_)
      return false;

    // Ensure that there is a valid reference at the pointer offset.
    BlockGraph::Reference ref;
    if (!block_->GetReference(offset, &ref))
      return false;
    if (size != 0 && ref.size() != size)
      return false;

    return typed_block->Init(ref.offset(), ref.referenced());
  }

  BlockGraph::Offset offset_;
  BlockPtr block_;
  size_t size_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TypedBlockImpl);
};

}  // namespace internal

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TYPED_BLOCK_INTERNAL_H_
