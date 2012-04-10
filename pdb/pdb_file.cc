// Copyright 2012 Google Inc.
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

#include "syzygy/pdb/pdb_file.h"

namespace pdb {

PdbFile::PdbFile() {
}

PdbFile::~PdbFile() {
  Clear();
}

void PdbFile::Clear() {
  streams_.clear();
}

PdbStream* PdbFile::GetStream(uint32 index) const {
  DCHECK_LT(index, streams_.size());
  return streams_[index];
}

size_t PdbFile::AppendStream(PdbStream* pdb_stream) {
  size_t index = streams_.size();
  streams_.push_back(pdb_stream);
  return index;
}

void PdbFile::ReplaceStream(uint32 index, PdbStream* pdb_stream) {
  DCHECK_LT(index, streams_.size());
  streams_[index] = pdb_stream;
}

}  // namespace pdb
