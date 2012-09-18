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
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace grinder {
namespace basic_block_util {

typedef core::RelativeAddress RelativeAddress;
typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;

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

typedef sym_util::ModuleInformation ModuleInformation;
typedef std::map<const ModuleInformation*, PdbInfo> PdbInfoMap;

// Loads a new or retrieves the cached PDB info for the given module. This
// also caches failures; it will not re-attempt to look up PDB information
// if a previous attempt for the same module failed.
// @param pdb_info_cache the cache of PDB info already seen.
// @param module_info the info representing the module to find PDB info for.
// @param pdb_info a pointer to the pdb info will be returned here.
// @return true on success, false otherwise.
bool GetPdbInfo(PdbInfoMap* pdb_info_cache,
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
