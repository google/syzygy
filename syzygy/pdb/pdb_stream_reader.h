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

#ifndef SYZYGY_PDB_PDB_STREAM_READER_H_
#define SYZYGY_PDB_PDB_STREAM_READER_H_

#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_stream.h"

namespace pdb {

// An adapter class that implements a BinaryStreamReader on a PdbStream.
class PdbStreamReader : public common::BinaryStreamReader {
 public:
  explicit PdbStreamReader(PdbStream* stream);
  PdbStreamReader();

  // @name BinaryStreamReader implementation.
  // @{
  bool Read(size_t len, void* out) override;
  size_t Position() const override;
  bool AtEnd() const override;
  // @}

  // @name Accessors.
  // @{
  scoped_refptr<PdbStream> stream() const { return stream_; }
  void set_stream(PdbStream* stream) { stream_ = stream; }
  // @}

 private:
  scoped_refptr<PdbStream> stream_;
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_STREAM_READER_H_
