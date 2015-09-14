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

#ifndef SYZYGY_PDB_PDB_STREAM_RECORD_H_
#define SYZYGY_PDB_PDB_STREAM_RECORD_H_

#include <cstdint>

#include "base/logging.h"
#include "base/strings/string16.h"
#include "syzygy/common/assertions.h"

namespace pdb {

// Forward declaration
class PdbStream;

class NumericConstant {
 public:
  enum Kind { CONSTANT_UNINITIALIZED, CONSTANT_UNSIGNED, CONSTANT_SIGNED };

  NumericConstant();

  // Acc
  Kind kind() const { return kind_; }
  uint64_t unsigned_value() const { return unsigned_value_; }
  int64_t signed_value() const { return signed_value_; }

  // We need the function to set this constant for us.
  friend bool ReadNumericConstant(PdbStream* stream, NumericConstant* constant);

 private:
  union {
    uint64_t unsigned_value_;
    uint64_t signed_value_;
  };

  Kind kind_;
};

// Reads string from pdb stream and converts it into a wide string.
// @param stream a pointer to the pdb stream.
// @param string_field pointer to the wide string object.
// @returns true on success, false on failure.
bool ReadWideString(PdbStream* stream, base::string16* string_field);

// Reads unsigned numeric leaf from pdb stream and stores it as 64-bit unsigned.
// @param stream a pointer to the pdb stream.
// @param data_field pointer to the numeric leaf object.
// @returns true on success, false on failure.
bool ReadUnsignedNumeric(PdbStream* stream, uint64_t* data_field);

// Reads unsigned numeric leaf from pdb stream and stores it as 64-bit unsigned.
// @param stream a pointer to the pdb stream.
// @param constant pointer to the numeric constant object.
// @returns true on success, false on failure.
bool ReadNumericConstant(PdbStream* stream, NumericConstant* constant);

// Reads basic type from pdb stream.
// @param stream a pointer to the pdb stream.
// @param basic_type a pointer to the destination object.
// @returns true on success, false on failure.
template <typename T>
bool ReadBasicType(PdbStream* stream, T* basic_type) {
  COMPILE_ASSERT_IS_POD(T);
  DCHECK(stream);
  DCHECK(basic_type);

  return stream->Read(basic_type, 1);
}

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_STREAM_RECORD_H_
