// Copyright 2015 Google Inc. All Rights Reserved.
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
// This defines BufferSerializer that can be used with the Assembler to assemble
// into a memory buffer.

#ifndef SYZYGY_ASSM_BUFFER_SERIALIZER_H_
#define SYZYGY_ASSM_BUFFER_SERIALIZER_H_

#include "syzygy/assm/assembler.h"

namespace assm {

// An InstructionSerializer class that assembles instructions into a memory
// buffer.
// The assembler should also be created using the desired target location to
// make correct references. The buffer passed in the constructor arguments is
// used for bounds checking in DCHECK mode.
class BufferSerializer : public AssemblerImpl::InstructionSerializer {
 public:
  // Creates a BufferSerializer object.
  // @param buffer A pointer to the buffer.
  // @param size The size of the buffer.
  BufferSerializer(uint8_t* buffer, size_t size)
      : buffer_(buffer), size_(size) {}

  // @name Accessors.
  // @{
  uint8_t* buffer() const { return buffer_; }
  size_t size() const { return size_; }
  // @}

  // @name Implementation of the InstructionSerializer interface.
  // @{
  typedef assm::AssemblerImpl::ReferenceInfo ReferenceInfo;
  void AppendInstruction(uint32_t location,
                         const uint8_t* bytes,
                         uint32_t num_bytes,
                         const ReferenceInfo* refs,
                         size_t num_refs) override {
    uint8_t* write_location = static_cast<uint8_t*>(0) + location;
    DCHECK_GE(write_location, buffer_);
    DCHECK_LE(write_location + num_bytes, buffer_ + size_);

    ::memcpy(write_location, bytes, num_bytes);
  }
  bool FinalizeLabel(uint32_t location,
                     const uint8_t* bytes,
                     size_t num_bytes) override {
    return false;  // No label support.
  }
  // @}

 private:
  uint8_t* buffer_;
  size_t size_;
};

}  // namespace assm

#endif  // SYZYGY_ASSM_BUFFER_SERIALIZER_H_
