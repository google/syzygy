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

#include "syzygy/grinder/grinder_util.h"

#include "base/files/file_util.h"
#include "mnemonics.h"  // NOLINT
#include "syzygy/common/defs.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"

namespace grinder {

bool GetBasicBlockAddresses(const base::FilePath& pdb_path,
                            RelativeAddressVector* bb_addresses) {
  DCHECK(bb_addresses != NULL);

  pdb::PdbFile pdb_file;
  pdb::PdbReader pdb_reader;
  if (!pdb_reader.Read(pdb_path, &pdb_file)) {
    LOG(ERROR) << "Failed to read PDB file: " << pdb_path.value();
    return false;
  }

  pdb::PdbInfoHeader70 pdb_header = {};
  pdb::NameStreamMap name_stream_map;
  if (!pdb::ReadHeaderInfoStream(pdb_file, &pdb_header, &name_stream_map)) {
    LOG(ERROR) << "Failed to read PDB header info stream for PDB file: "
               << pdb_path.value();
    return false;
  }

  pdb::NameStreamMap::const_iterator stream_id_it =
      name_stream_map.find(common::kBasicBlockRangesStreamName);
  if (stream_id_it == name_stream_map.end()) {
    LOG(ERROR) << "Failed to find stream \""
               << common::kBasicBlockRangesStreamName << "\" in PDB file: "
               << pdb_path.value();
    return false;
  }

  scoped_refptr<pdb::PdbStream> stream =
      pdb_file.GetStream(stream_id_it->second);
  if (stream.get() == NULL) {
    LOG(ERROR) << "No stream with id " << stream_id_it->second
               << " in PDB file: " << pdb_path.value();
    return false;
  }

  const size_t kElementSize = sizeof(RelativeAddressVector::value_type);
  size_t num_elements = stream->length() / kElementSize;
  bb_addresses->resize(num_elements);
  if (num_elements != 0 &&
      !stream->ReadBytesAt(0, num_elements * kElementSize,
                           &bb_addresses->at(0))) {
    LOG(ERROR) << "Failed to parse basic block range stream from PDB file: "
               << pdb_path.value();
    return false;
  }

  return true;
}

}  // namespace grinder
