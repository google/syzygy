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

#include "base/strings/string16.h"

namespace pdb {

// Forward declaration
class PdbStream;

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

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_STREAM_RECORD_H_
