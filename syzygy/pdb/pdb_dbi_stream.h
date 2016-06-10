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
//
// This header file provides a utility class to read a Dbi stream from a PDB and
// give access to its data.
//
// The Dbi stream of a PDB contains different substream containing various
// debug information. These different substreams are (see pdb_data.h for more
// details on the sub-structures used in each substream):
// - The DbiHeader;
// - A set of DbiModuleInfoBase;
// - A set of DbiSectionContrib;
// - A set of DbiSectionMapItem;
// - A set of file informations;
// - The TS map (but this substream is always empty so we ignore it);
// - The EC informations; and
// - The DbiDbgHeader.

#ifndef SYZYGY_PDB_PDB_DBI_STREAM_H_
#define SYZYGY_PDB_PDB_DBI_STREAM_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

// This class represent a module info element as it is present in the module
// info substream of the Dbi stream of a PDB file. It extends the
// DbiModuleInfoBase structure by adding some fields with variable length.
class DbiModuleInfo {
 public:
  // Default constructor.
  DbiModuleInfo() {
    memset(&module_info_base_, 0, sizeof(module_info_base_));
  }

  // Copy constructor. It is required because this class is used in a STL
  // container.
  DbiModuleInfo(const DbiModuleInfo& other)
      : module_info_base_(other.module_info_base_),
        module_name_(other.module_name_),
        object_name_(other.object_name_) {
  }

  // Destructor.
  ~DbiModuleInfo() {
  }

  // Reads a module info from a PDB stream.
  //
  // @param stream The parser for the module info. It must be positioned
  //     at the beginning of a module info.
  // @returns true on success, false otherwise.
  bool Read(common::BinaryStreamParser* parser);

  // @name Accessors.
  // @{
  const DbiModuleInfoBase& module_info_base() const {
    return module_info_base_;
  }
  const std::string& module_name() const { return module_name_; }
  const std::string& object_name() const { return object_name_; }
  // @}

 private:
  DbiModuleInfoBase module_info_base_;
  std::string module_name_;
  std::string object_name_;
};

// This class represent the Dbi stream of a PDB. It contains some serialization
// functions to be able to load the different substreams.
class DbiStream {
 public:
  // Typedefs used to store the content of the Dbi Stream.
  typedef std::vector<DbiModuleInfo> DbiModuleVector;
  typedef std::vector<DbiSectionContrib> DbiSectionContribVector;
  typedef std::vector<uint32_t> DbiFileInfoFileList;
  typedef std::vector<DbiFileInfoFileList> DbiFileInfoVector;
  typedef std::map<uint32_t, std::string> DbiFileInfoNameMap;
  typedef std::pair<DbiFileInfoVector, DbiFileInfoNameMap> DbiFileInfo;
  typedef std::map<uint16_t, DbiSectionMapItem> DbiSectionMap;
  typedef OffsetStringMap DbiEcInfoVector;

  // Default constructor.
  DbiStream() {
  }

  // Copy constructor.
  DbiStream(const DbiStream& other)
      : header_(other.header_),
        modules_(other.modules_),
        section_contribs_(other.section_contribs_),
        section_map_(other.section_map_),
        file_info_(other.file_info_),
        ec_info_vector_(other.ec_info_vector_),
        dbg_header_(other.dbg_header_) {
  }

  // Destructor.
  ~DbiStream() {
  }

  // @name Accessors.
  // @{
  const DbiDbgHeader& dbg_header() const { return dbg_header_; }
  const DbiHeader& header() const { return header_; }
  const DbiModuleVector& modules() const { return modules_; }
  const DbiSectionMap& section_map() const { return section_map_; }
  // @}

  // Reads the Dbi stream of a PDB.
  //
  // @param stream The stream containing the Dbi data.
  // @returns true on success, false otherwise.
  bool Read(pdb::PdbStream* stream);

 private:
  // Serialization of the Dbi header.
  //
  // @param stream The stream containing the Dbi header.
  // @returns true on success, false otherwise.
  bool ReadDbiHeaders(pdb::PdbStream* stream);

  // Serialization of the module info substream.
  //
  // @param stream The stream containing the module info substream.
  // @returns true on success, false otherwise.
  bool ReadDbiModuleInfo(pdb::PdbStream* stream);

  // Serialization of the section contribs substream.
  //
  // @param stream The stream containing the section contribs substream.
  // @returns true on success, false otherwise.
  bool ReadDbiSectionContribs(pdb::PdbStream* stream);

  // Serialization of the section map substream.
  //
  // @param stream The stream containing the section map substream.
  // @returns true on success, false otherwise.
  bool ReadDbiSectionMap(pdb::PdbStream* stream);

  // Serialization of the file info substream.
  //
  // @param stream The stream containing the file info substream.
  // @returns true on success, false otherwise.
  bool ReadDbiFileInfo(pdb::PdbStream* stream);

  // Serialization of the file-blocks section of the file info substream.
  //
  // @param stream The stream containing the file info substream.
  // @param file_blocks_table_size The size of the file-blocks table.
  // @param file_blocks_table_start The address of the beginning of the
  //     file-blocks table in the stream.
  // @param offset_table_size The size of the offset table.
  // @param offset_table_start The address of the beginning of the
  //     offset table in the stream.
  // @returns true on success, false otherwise.
  bool ReadDbiFileInfoBlocks(pdb::PdbStream* stream,
                             uint16_t file_blocks_table_size,
                             size_t file_blocks_table_start,
                             size_t offset_table_start);

  // Serialization of the name table in the file info substream.
  //
  // @param stream The stream containing the file info substream.
  // @param name_table_start The address of the beginning of the name table in
  //     the stream.
  // @param name_table_end The address of the end of the name table in the
  //     stream.
  // @returns true on success, false otherwise.
  bool ReadDbiFileNameTable(pdb::PdbStream* stream,
                            size_t name_table_start,
                            size_t name_table_end);

  // Serialization of the EC info substream. For now we don't know for what the
  // EC acronym stand for. This substream is composed of a list of source file
  // and PDB names.
  //
  // @param stream The stream containing the EC info substream.
  // @returns true on success, false otherwise.
  bool ReadDbiECInfo(pdb::PdbStream* stream);

  // Header of the stream.
  DbiHeader header_;

  // All the modules we contain.
  DbiModuleVector modules_;

  // All section contributions we contain.
  DbiSectionContribVector section_contribs_;

  // Map of the sections that we contain.
  DbiSectionMap section_map_;

  // File info that we contain.
  DbiFileInfo file_info_;

  // Vector of the EC info that we contain.
  DbiEcInfoVector ec_info_vector_;

  // Debug header.
  DbiDbgHeader dbg_header_;
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DBI_STREAM_H_
