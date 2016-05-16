// Copyright 2011 Google Inc. All Rights Reserved.
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
// Implementation class to gather per-process, per-module working set
// statistics.

#ifndef SYZYGY_WSDUMP_PROCESS_WORKING_SET_H_
#define SYZYGY_WSDUMP_PROCESS_WORKING_SET_H_

#include <windows.h>
#include <memory>
#include <string>
#include <vector>

namespace core {
  template <typename AddressType, typename SizeType, typename ItemType>
  class AddressSpace;
};
struct _PSAPI_WORKING_SET_INFORMATION;
typedef struct _PSAPI_WORKING_SET_INFORMATION PSAPI_WORKING_SET_INFORMATION;

namespace wsdump {

// Captures working set for a given process at a point in time,
// summarizes per-module as well as overall statistics.
class ProcessWorkingSet {
 public:
  // Non-module stats.
  struct Stats {
    Stats() { memset(this, 0, sizeof(*this)); }

    size_t pages;
    size_t shareable_pages;
    size_t shared_pages;
    size_t read_only_pages;
    size_t writable_pages;
    size_t executable_pages;
  };

  // Per-module stats.
  struct ModuleStats : public Stats {
    std::wstring module_name;
  };
  typedef std::vector<ModuleStats> ModuleStatsVector;

  // Initialize working set statistics for the given process_id.
  // @returns true on success, false on failure.
  // @note total_stats(), non_module_stats() and module_stats() are valid only
  //      after a successful call call to Initialize.
  bool Initialize(DWORD process_id);

  // @returns overall tally for the whole process.
  const Stats& total_stats() const { return total_stats_; }

  // @returns tally for working set pages that don't belong to modules,
  //      e.g. pages that belong to heaps, stacks, mapped files, etc.
  const Stats& non_module_stats() const { return non_module_stats_; }

  // @returns per module tallies.
  const ModuleStatsVector& module_stats() const { return module_stats_; }

 protected:
  // These are protected members to allow unittesting them.
  typedef std::unique_ptr<PSAPI_WORKING_SET_INFORMATION> ScopedWsPtr;
  static bool CaptureWorkingSet(HANDLE process, ScopedWsPtr* working_set);

  typedef core::AddressSpace<size_t, size_t, std::wstring> ModuleAddressSpace;
  static bool CaptureModules(DWORD process_id, ModuleAddressSpace* modules);

  // Storage for stats.
  Stats total_stats_;
  Stats non_module_stats_;
  ModuleStatsVector module_stats_;
};

}  // namespace wsdump

#endif  // SYZYGY_WSDUMP_PROCESS_WORKING_SET_H_
