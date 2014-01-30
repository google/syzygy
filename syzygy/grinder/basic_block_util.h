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
// Declares structure and functions useful to grinders that process basic-
// block frequency data.

#ifndef SYZYGY_GRINDER_BASIC_BLOCK_UTIL_H_
#define SYZYGY_GRINDER_BASIC_BLOCK_UTIL_H_

#include <map>
#include <vector>

#include "base/files/file_path.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/grinder/line_info.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace grinder {
namespace basic_block_util {

// Address related types.
typedef core::RelativeAddress RelativeAddress;
typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;

// Module information.
typedef pe::ModuleInformation ModuleInformation;

// Compares module information on identity properties alone.
struct ModuleIdentityComparator {
  bool operator()(const ModuleInformation& lhs, const ModuleInformation& rhs);
};

// Type definitions for the basic block entry count data.
typedef int32 EntryCountType;
typedef int32 BasicBlockOffset;
// An entry count map maps from the relative virtual address of the first
// instruction or data byte in the basic block, to its entry count.
typedef std::map<BasicBlockOffset, EntryCountType> EntryCountMap;

typedef std::map<ModuleInformation,
                 EntryCountMap,
                 ModuleIdentityComparator> ModuleEntryCountMap;

// Type definitions for the indexed frequency data.
typedef std::pair<RelativeAddress, size_t> IndexedFrequencyOffset;
typedef std::map<IndexedFrequencyOffset, EntryCountType> IndexedFrequencyMap;
// The information kept for each module.
struct IndexedFrequencyInformation {
  uint32 num_entries;
  uint32 num_columns;
  common::IndexedFrequencyData::DataType data_type;
  uint8 frequency_size;
  IndexedFrequencyMap frequency_map;
};

bool operator==(const IndexedFrequencyInformation& lhs,
                const IndexedFrequencyInformation& rhs);

// An indexed frequency map maps from the relative virtual address of the first
// instruction or data byte in the basic block, to its frequencies.
typedef std::map<ModuleInformation,
                 IndexedFrequencyInformation,
                 ModuleIdentityComparator> ModuleIndexedFrequencyMap;

// This structure holds the information extracted from a PDB file for a
// given module.
struct PdbInfo {
  // The path to this PDB file.
  base::FilePath pdb_path;

  // Line and coverage information for all the source files associated with
  // a particular PDB.
  LineInfo line_info;

  // Basic-block addresses for the module associated with a particular PDB.
  // Used to transform basic-block frequency data to line visits via line_info.
  RelativeAddressRangeVector bb_ranges;
};

typedef std::map<ModuleInformation,
                 PdbInfo,
                 ModuleIdentityComparator> PdbInfoMap;

bool FindIndexedFrequencyInfo(
    const pe::PEFile::Signature& signature,
    const ModuleIndexedFrequencyMap& module_entry_map,
    const IndexedFrequencyInformation** information);

// A helper function to populate @p frequencies from a branching file for a
// given module signature.
// @param file the file containing branching information.
// @param signature the signature of the module to retrieve.
// @param frequencies receives the module branch frequencies.
// @returns true on success, false otherwise.
bool LoadBranchStatisticsFromFile(const base::FilePath& file,
                                  const pe::PEFile::Signature& signature,
                                  IndexedFrequencyMap* frequencies);

// A helper function to populate @p bb_ranges from the PDB file given by
// @p pdb_path.
// @returns true on success, false otherwise.
bool LoadBasicBlockRanges(const base::FilePath& pdb_path,
                          RelativeAddressRangeVector* bb_ranges);

// Loads a new or retrieves the cached PDB info for the given module. This
// also caches failures; it will not re-attempt to look up PDB information
// if a previous attempt for the same module failed.
// @param pdb_info_cache the cache of PDB info already seen.
// @param module_info the info representing the module to find PDB info for.
// @param pdb_info a pointer to the pdb info will be returned here.
// @returns true on success, false otherwise.
bool LoadPdbInfo(PdbInfoMap* pdb_info_cache,
                 const ModuleInformation& module_info,
                 PdbInfo** pdb_info);

// @returns true if the given @p size is a valid frequency size.
bool IsValidFrequencySize(size_t size);

// @returns the frequency value contained in @p data for the basic_block given
//     by @p bb_id.
uint32 GetFrequency(const TraceIndexedFrequencyData* data,
                    size_t bb_id,
                    size_t column);

}  // namespace basic_block_util
}  // namespace grinder

#endif  // SYZYGY_GRINDER_BASIC_BLOCK_UTIL_H_
