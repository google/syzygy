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

#include "syzygy/pdb/pdb_data.h"

namespace pdb {

// Forward declarations.
class PdbStream;

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
  // @param stream The stream containing the module info. It must be positioned
  //     at the beginning of a module info.
  // @returns true on success, false otherwise.
  bool Read(pdb::PdbStream* stream);

  // @name Accessors.
  // @{
  const DbiModuleInfoBase& module_info_base() { return module_info_base_; }
  const std::string& module_name() { return module_name_; }
  const std::string& object_name() { return object_name_; }
  // @}

 private:
  DbiModuleInfoBase module_info_base_;
  std::string module_name_;
  std::string object_name_;
};

// This class represent the Dbi stream of a PDB. It contains some serialization
// functions to be able to load the different substream.
class DbiStream {
 public:
  // Typedefs used to store the content of the Dbi Stream.
  typedef std::vector<DbiModuleInfo> DbiModuleVector;
  typedef std::vector<DbiSectionContrib> DbiSectionContribVector;
  typedef std::vector<size_t> DbiFileInfoFileList;
  typedef std::vector<DbiFileInfoFileList> DbiFileInfoVector;
  typedef std::map<size_t, std::string> DbiFileInfoNameMap;
  typedef std::pair<DbiFileInfoVector, DbiFileInfoNameMap> DbiFileInfo;
  typedef std::map<uint16, DbiSectionMapItem> DbiSectionMap;
  typedef std::map<size_t, std::string> DbiEcInfoMap;

  // Default constructor.
  DbiStream() {
  }

  // Copy constructor.
  DbiStream(const DbiStream& other)
      : header_(other.header_),
        modules_(other.modules_),
        sections_contribs_(other.sections_contribs_),
        section_map_(other.section_map_),
        file_info_(other.file_info_),
        ec_info_map_(other.ec_info_map_),
        dbg_header_(other.dbg_header_) {
  }

  // Destructor.
  ~DbiStream() {
  }

  // @name Accessors.
  // @{
  const DbiDbgHeader& dbg_header() const {return dbg_header_; }
  const DbiHeader& header() const {return header_; }
  // @}

  // Reads the Dbi stream of a PDB.
  //
  // @param stream The stream containing the Dbi data.
  // @returns true on success, false otherwise.
  bool Read(pdb::PdbStream* stream);

 private:
  // Serialization of the module info substream.
  //
  // @param stream The stream containing the module info substream.
  // @returns true on success, false otherwise.
  bool ReadDbiModuleInfo(pdb::PdbStream* stream);

  // Serialization of the Dbi header.
  //
  // @param stream The stream containing the Dbi header.
  // @returns true on success, false otherwise.
  bool ReadDbiHeaders(pdb::PdbStream* stream);

  // Header of the stream.
  DbiHeader header_;

  // All the modules we contain.
  DbiModuleVector modules_;

  // All section contributions we contain.
  // TODO(sebmarchand): Read this substream.
  DbiSectionContribVector sections_contribs_;

  // Map of the sections that we contain.
  // TODO(sebmarchand): Read this substream.
  DbiSectionMap section_map_;

  // File info that we contain.
  // TODO(sebmarchand): Read this substream.
  DbiFileInfo file_info_;

  // Map of the EC info that we contain.
  // TODO(sebmarchand): Read this substream.
  DbiEcInfoMap ec_info_map_;

  // Debug header.
  DbiDbgHeader dbg_header_;
};

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_DBI_STREAM_H_
