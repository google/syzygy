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

#include "syzygy/pdb/pdb_dbi_stream.h"

#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

bool DbiModuleInfo::Read(pdb::PdbStream* stream) {
  DCHECK(stream != NULL);

  if (!stream->Read(&module_info_base_, 1) ||
      !ReadString(stream, &module_name_) ||
      !ReadString(stream, &object_name_) ||
      !stream->Seek(common::AlignUp(stream->pos(), 4))) {
    LOG(ERROR) << "Unable to read module information.";
    return false;
  }

  return true;
}

// Reads the header from the Dbi stream of the PDB.
bool DbiStream::ReadDbiHeaders(pdb::PdbStream* stream) {
  DCHECK(stream != NULL);

  if (!stream->Seek(0) || !stream->Read(&header_, 1)) {
    LOG(ERROR) << "Unable to read the header of the Dbi Stream.";
    return false;
  }

  if (!stream->Seek(pdb::GetDbiDbgHeaderOffset(header_)) ||
      !stream->Read(&dbg_header_, 1)) {
    LOG(ERROR) << "Unable to read Dbg header of the Dbi Stream.";
    return false;
  }

  return true;
}

// Reads the module info substream from the Dbi stream of the PDB.
bool DbiStream::ReadDbiModuleInfo(pdb::PdbStream* stream) {
  DCHECK(stream != NULL);

  // This substream starts just after the Dbi header in the Dbi stream.
  size_t module_start = sizeof(pdb::DbiHeader);
  size_t module_end = module_start + header_.gp_modi_size;
  if (!stream->Seek(module_start)) {
    LOG(ERROR) << "Unable to read the module information substream of the Dbi "
               << "stream.";
    return false;
  }

  // Read each module info block.
  while (stream->pos() < module_end) {
    DbiModuleInfo module_info;
    if (!module_info.Read(stream))
      return false;
    modules_.push_back(module_info);
  }

  if (stream->pos() != module_end) {
    LOG(ERROR) << "Module info substream of the Dbi stream is not valid.";
    return false;
  }

  return true;
}

bool DbiStream::Read(pdb::PdbStream* stream ) {
  DCHECK(stream != NULL);

  if (!ReadDbiHeaders(stream))
    return false;

  if (!ReadDbiModuleInfo(stream))
    return false;

  return true;
}

}  // namespace pdb
