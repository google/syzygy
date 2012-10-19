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

#include "base/file_path.h"
#include "sawbuck/sym_util/types.h"
#include "syzygy/core/address_space.h"
#include "syzygy/grinder/line_info.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace grinder {
namespace basic_block_util {

// Address related types.
typedef core::RelativeAddress RelativeAddress;
typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;

// A wrapper class that inverts RelativeAddressRangeVector and interprets it
// as a map from a basic-block address to its id.
class BasicBlockIdMap {
 public:
  typedef size_t BasicBlockId;
  typedef std::pair<RelativeAddress, BasicBlockId> ValueType;
  typedef std::vector<ValueType> ContainerType;
  typedef ContainerType::const_iterator ConstIterator;

  // Default constructor.
  BasicBlockIdMap();

  // Initialize the basic-block ID map from a relative address range vector.
  bool Init(const RelativeAddressRangeVector& bb_ranges);

  // Find the basic-block ID for the basic-block range starting with @p bb_addr.
  bool Find(const RelativeAddress& bb_addr, BasicBlockId* id) const;

  // Iterator functions.
  // @{
  ConstIterator Begin() const { return container_.begin(); }
  ConstIterator End() const { return container_.end(); }
  ConstIterator LowerBound(const RelativeAddress& addr) const {
    return std::lower_bound(Begin(), End(), addr, AddrCompareLess());
  }
  ConstIterator UpperBound(const RelativeAddress& addr) const {
    return std::upper_bound(Begin(), End(), addr, AddrCompareLess());
  }
  // @}

  // Get the number of basic-blocks represented in this basic-block ID map.
  size_t Size() const { return container_.size(); }

 protected:
  // A comparator to use when searching the sorted range/id vector.
  struct AddrCompareLess
      : public std::binary_function<ValueType, ValueType, bool> {
    bool operator()(const ValueType& lhs, const ValueType& rhs) const {
      return lhs.first < rhs.first;
    }
    bool operator()(const ValueType& lhs, const RelativeAddress& rhs) const {
      return lhs.first < rhs;
    }
    bool operator()(const RelativeAddress& lhs, const ValueType& rhs) const {
      return lhs < rhs.first;
    }
  };

  // The map from a range to the corresponding ID.
  ContainerType container_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockIdMap);
};

// Module information.
typedef sym_util::ModuleInformation ModuleInformation;

// Type definitions for the basic block entry count data.
typedef uint32 EntryCountType;
typedef std::vector<EntryCountType> EntryCountVector;
typedef std::map<ModuleInformation, EntryCountVector> EntryCountMap;

// This structure holds the information extracted from a PDB file for a
// given module.
struct PdbInfo {
  // The path to this PDB file.
  FilePath pdb_path;

  // Line and coverage information for all the source files associated with
  // a particular PDB.
  LineInfo line_info;

  // Basic-block addresses for the module associated with a particular PDB.
  // Used to transform basic-block frequency data to line visits via
  // line_info.
  RelativeAddressRangeVector bb_ranges;
};

typedef std::map<const ModuleInformation*, PdbInfo> PdbInfoMap;

// A helper function to populate a ModuleInforamtion structure from a PE
// signature.
void InitModuleInfo(const pe::PEFile::Signature& signature,
                    ModuleInformation* module_info);

// Given a module @p signature, find the matching @p module_information
// and @p entry_count_vector in the given @p entry_count_map.
bool FindEntryCountVector(const pe::PEFile::Signature& signature,
                          const EntryCountMap& entry_count_map,
                          const EntryCountVector** entry_count_vector);

// A helper function to populate @p bb_ranges from the PDB file given by
// @p pdb_path.
// @returns true on successs, false otherwise.
bool LoadBasicBlockRanges(const FilePath& pdb_path,
                          RelativeAddressRangeVector* bb_ranges);

// Loads a new or retrieves the cached PDB info for the given module. This
// also caches failures; it will not re-attempt to look up PDB information
// if a previous attempt for the same module failed.
// @param pdb_info_cache the cache of PDB info already seen.
// @param module_info the info representing the module to find PDB info for.
// @param pdb_info a pointer to the pdb info will be returned here.
// @return true on success, false otherwise.
bool LoadPdbInfo(PdbInfoMap* pdb_info_cache,
                 const ModuleInformation* module_info,
                 PdbInfo** pdb_info);

// @returns true if the given @p size is a valid frequency size.
bool IsValidFrequencySize(size_t size);

// @returns the frequency value contained in @p data for the basic_block given
//     by @p bb_id.
uint32 GetFrequency(const TraceBasicBlockFrequencyData* data,  size_t bb_id);

}  // namespace basic_block_util
}  // namespace grinder

#endif  // SYZYGY_GRINDER_BASIC_BLOCK_UTIL_H_
