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

#include "syzygy/instrument/mutators/add_bb_ranges_stream.h"

#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/pdb/pdb_byte_stream.h"

namespace instrument {
namespace mutators {

const char AddBasicBlockRangesStreamPdbMutator::kMutatorName[] =
    "AddBasicBlockRangesStreamPdbMutator";

bool AddBasicBlockRangesStreamPdbMutator::AddNamedStreams(
    const pdb::PdbFile& pdb_file) {
  // Create the basic block ranges stream.
  scoped_refptr<pdb::PdbByteStream> bb_stream(new pdb::PdbByteStream);
  if (bb_ranges_.size() > 0) {
    CHECK(bb_stream->Init(reinterpret_cast<const uint8*>(&bb_ranges_.at(0)),
                          bb_ranges_.size() * sizeof(bb_ranges_.at(0))));
  }

  // Create the conditional ranges stream.
  scoped_refptr<pdb::PdbByteStream> cond_stream(new pdb::PdbByteStream);
  if (conditional_ranges_.size() > 0) {
    CHECK(cond_stream->Init(
        reinterpret_cast<const uint8*>(&conditional_ranges_.at(0)),
        conditional_ranges_.size() * sizeof(conditional_ranges_.at(0))));
  }

  // Add the BB stream to the PDB.
  if (!SetNamedStream(common::kBasicBlockRangesStreamName, bb_stream.get())) {
    // This should not happen, as it indicates we are trying to doubly
    // instrument a given binary.
    LOG(ERROR) << "Basic-block ranges stream already exists.";
    return false;
  }

  // Add the conditional ranges stream to the PDB.
  if (!SetNamedStream(common::kConditionalRangesStreamName,
                      cond_stream.get())) {
    // This should not happen, as it indicates we are trying to doubly
    // instrument a given binary.
    LOG(ERROR) << "Conditional ranges stream already exists.";
    return false;
  }

  return true;
}

}  // namespace mutators
}  // namespace instrument
