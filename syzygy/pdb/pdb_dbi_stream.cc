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

#include "syzygy/pdb/pdb_dbi_stream.h"

#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_constants.h"
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

// Reads the section contribs substream from the Dbi stream of the PDB.
bool DbiStream::ReadDbiSectionContribs(pdb::PdbStream* stream) {
  DCHECK(stream != NULL);

  size_t section_contribs_start = sizeof(pdb::DbiHeader) + header_.gp_modi_size;
  size_t section_contribs_end =
      section_contribs_start + header_.section_contribution_size;
  uint32 signature = 0;

  if (!stream->Seek(section_contribs_start) || !stream->Read(&signature, 1)) {
    LOG(ERROR) << "Unable to seek to section contributions substream.";
    return false;
  }

  if (signature != kPdbDbiSectionContribsSignature) {
    LOG(ERROR) << "Unexpected signature for the section contribs substream. "
               << "Expected "
               << base::StringPrintf("0x%08X", kPdbDbiSectionContribsSignature)
               << ", read "
               << base::StringPrintf("0x%08X", signature) << ".";
    return false;
  }

  size_t section_contrib_count =
    (section_contribs_end - stream->pos()) / sizeof(DbiSectionContrib);

  if (!stream->Read(&section_contribs_, section_contrib_count)) {
    LOG(ERROR) << "Unable to read section contributions.";
    return false;
  }

  if (stream->pos() != section_contribs_end) {
    LOG(ERROR) << "Section contribs substream of the Dbi stream is not valid.";
    return false;
  }

  return true;
}

// Reads the section map substream from the Dbi stream of the PDB.
bool DbiStream::ReadDbiSectionMap(pdb::PdbStream* stream) {
  DCHECK(stream != NULL);

  size_t section_map_start = sizeof(pdb::DbiHeader)
      + header_.gp_modi_size
      + header_.section_contribution_size;
  size_t section_map_end = section_map_start + header_.section_map_size;
  uint16 number_of_sections = 0;

  if (!stream->Seek(section_map_start)) {
    LOG(ERROR) << "Unable to seek to section map substream.";
    return false;
  }

  if (!stream->Read(&number_of_sections, 1)) {
    LOG(ERROR) << "Unable to read the length of the section map in the Dbi "
               << "stream.";
    return false;
  }

  // The number of section appears to be present twice. This check ensure that
  // the value are always equals. If it's not it'll give us a sample to
  // understand what's this value.

  uint16 number_of_sections_copy = 0;
  if (!stream->Read(&number_of_sections_copy, 1)) {
    LOG(ERROR) << "Unable to read the copy of the length of the section map in "
               << "the Dbi stream.";
    return false;
  }

  if (number_of_sections != number_of_sections_copy) {
    LOG(ERROR) << "Mismatched values for the length of the section map ("
               <<  number_of_sections << " vs "<< number_of_sections_copy
               << ").";
    return false;
  }

  while (stream->pos() < section_map_end) {
    DbiSectionMapItem section_map_item;
    stream->Read(&section_map_item, 1);
    section_map_[section_map_item.section_number] = section_map_item;
  }

  if (section_map_.size() != number_of_sections) {
    LOG(ERROR) << "Unexpected number of sections in the section map (expected "
               << number_of_sections << ", read " << section_map_.size()
               << ").";
    return false;
  }

  if (stream->pos() != section_map_end) {
    LOG(ERROR) << "Section map substream of the Dbi stream is not valid.";
    return false;
  }

  return true;
}

// Reads the file info substream from the Dbi stream of the PDB.
// The structure of this substream is:
// Header | File-blocks table | Offset table | Name table.
// - The header contains the number of entries in the File-blocks table (16
//    bits) followed by the number of entries in the offset table (16 bits). You
//   have to multiply each size by 4 to obtain the size in bytes.
// - The file-blocks table is divided in 2 parts. The first part contains the
//   starting index of each block (16 bits) and the second one contains
//   the length of these blocks. These value refer to the offset table. It
//   seems that there's always a last block with a starting value equal to the
//   length of the offset table and a length of 0 at the end of this table.
// - The offset table contains offsets to the beginning of file names in the
//   name table. These offsets are relative to the beginning of the name table.
// - The name table contain all the filenames used in this substream.
bool DbiStream::ReadDbiFileInfo(pdb::PdbStream* stream) {
  DCHECK(stream != NULL);

  size_t file_info_start = sizeof(pdb::DbiHeader)
      + header_.gp_modi_size
      + header_.section_contribution_size
      + header_.section_map_size;
  size_t file_info_end = file_info_start + header_.file_info_size;
  uint16 file_blocks_table_size = 0;
  uint16 offset_table_size = 0;

  if (!stream->Seek(file_info_start)) {
    LOG(ERROR) << "Unable to seek to file info substream.";
    return false;
  }

  if (!stream->Read(&file_blocks_table_size, 1) ||
      !stream->Read(&offset_table_size, 1)) {
    LOG(ERROR) << "Unable to read the header of the file info substream.";
    return false;
  }

  // Calculate the starting address of the different sections of this substream.
  size_t file_blocks_table_start = stream->pos();
  size_t offset_table_start = stream->pos()
      + file_blocks_table_size*sizeof(size_t);
  size_t name_table_start = offset_table_start
      + offset_table_size*sizeof(size_t);

  if (!ReadDbiFileInfoBlocks(stream,
                             file_blocks_table_size,
                             file_blocks_table_start,
                             offset_table_size,
                             offset_table_start)) {
    return false;
  }

  // Read the name table in this substream.
  if (!ReadDbiFileNameTable(stream,
                            name_table_start,
                            file_info_end)) {
    return false;
  }

  return true;
}

bool DbiStream::ReadDbiFileInfoBlocks(pdb::PdbStream* stream,
                                      uint16 file_blocks_table_size,
                                      size_t file_blocks_table_start,
                                      uint16 offset_table_size,
                                      size_t offset_table_start) {
  file_info_.first.resize(file_blocks_table_size);
  // Read information about each block of the file info substream.
  for (int i = 0; i < file_blocks_table_size; ++i) {
    uint16 block_start = 0;
    uint16 block_length = 0;

    if (!stream->Seek(file_blocks_table_start + i * sizeof(block_start)) ||
        !stream->Read(&block_start, 1) ||
        !stream->Seek(file_blocks_table_start
            + (file_blocks_table_size + i)*sizeof(block_start)) ||
        !stream->Read(&block_length, 1)) {
      LOG(ERROR) << "Unable to read the file info substream.";
      return false;
    }

    // Fill the file list.
    if (!stream->Seek(offset_table_start + block_start * sizeof(size_t))) {
      LOG(ERROR) << "Unable to seek to the beginning of a block in the name "
                 << " info substream (block index = " << block_start << ").";
      return false;
    }

    if (!stream->Read(&file_info_.first.at(i), block_length)) {
      LOG(ERROR) << "Unable to read the file info substream.";
      return false;
    }
  }

  return true;
}

// It would be useful to move this code to a more generic function if we see
// this structure somewhere else in the PDB.
bool DbiStream::ReadDbiFileNameTable(pdb::PdbStream* stream,
                                     size_t name_table_start,
                                     size_t name_table_end) {
  if (!stream->Seek(name_table_start)) {
    LOG(ERROR) << "Unable to seek to the name table of the file info "
               << "substream.";
    return false;
  }

  while (stream->pos() < name_table_end)  {
    std::string filename;
    size_t pos = stream->pos() - name_table_start;
    if (!ReadString(stream, &filename)) {
      LOG(ERROR) << "Unable to read the name table of the file info substream.";
      return false;
    }
    file_info_.second.insert(std::make_pair(pos, filename));
  }

  if (stream->pos() != name_table_end) {
    LOG(ERROR) << "File info substream of the Dbi stream is not valid.";
    return false;
  }

  return true;
}

bool DbiStream::ReadDbiECInfo(pdb::PdbStream* stream) {
  // It's important to note that the ec_info_size field appears after the
  // dbg_header_size field in the header of this stream but the EC info
  // substream is located before the DbgHeader substream.
  size_t ec_info_start = sizeof(pdb::DbiHeader)
      + header_.gp_modi_size
      + header_.section_contribution_size
      + header_.section_map_size
      + header_.file_info_size
      + header_.ts_map_size;
  size_t ec_info_end = ec_info_start + header_.ec_info_size;

  return ReadStringTable(stream,
                         "EC info",
                         ec_info_start,
                         ec_info_end,
                         &ec_info_vector_);
}

bool DbiStream::Read(pdb::PdbStream* stream ) {
  DCHECK(stream != NULL);

  if (!ReadDbiHeaders(stream))
    return false;

  if (!ReadDbiModuleInfo(stream))
    return false;

  if (!ReadDbiSectionContribs(stream))
    return false;

  if (!ReadDbiSectionMap(stream))
    return false;

  if (!ReadDbiFileInfo(stream))
    return false;

  if (header_.ts_map_size != 0) {
    LOG(ERROR) << "The length of the TS map is expected to be null but we've "
               << "read a length of " << header_.ts_map_size << ".";
    return false;
  }

  if (!ReadDbiECInfo(stream))
    return false;

  return true;
}

}  // namespace pdb
