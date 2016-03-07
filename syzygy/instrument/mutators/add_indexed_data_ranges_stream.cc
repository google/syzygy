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

#include "syzygy/instrument/mutators/add_indexed_data_ranges_stream.h"

#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/pdb/pdb_byte_stream.h"

namespace instrument {
namespace mutators {

const char AddIndexedDataRangesStreamPdbMutator::kMutatorName[] =
    "AddIndexedDataRangesStreamPdbMutator";

bool AddIndexedDataRangesStreamPdbMutator::AddNamedStreams(
    const pdb::PdbFile& pdb_file) {
  if (indexed_data_ranges_.size() == 0) {
    LOG(INFO) << "Indexed data addresses vector is empty. Not adding stream.";
    return true;
  }

  // Create the stream.
  scoped_refptr<pdb::PdbByteStream> stream(new pdb::PdbByteStream);
  CHECK(stream->Init(
      reinterpret_cast<const uint8_t*>(&indexed_data_ranges_.at(0)),
      indexed_data_ranges_.size() * sizeof(indexed_data_ranges_.at(0))));

  // Add the stream to the PDB.
  if (!SetNamedStream(stream_name_.c_str(), stream.get())) {
    // This should not happen, as it indicates we are trying to doubly
    // instrument a given binary.
    LOG(ERROR) << "Indexed data ranges stream already exists.";
    return false;
  }

  return true;
}

}  // namespace mutators
}  // namespace instrument
