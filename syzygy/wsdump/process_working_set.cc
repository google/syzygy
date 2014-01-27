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

#include "syzygy/wsdump/process_working_set.h"

#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <map>

#include "base/memory/scoped_ptr.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/core/address_space.h"

namespace wsdump {

namespace {

const size_t kPageSize = 4096;
// These are inferred from the MSDN page for QueryWorkingSet.
const int kPageReadOnly = 0x001;
const int kPageExecute = 0x002;
const int kPageExecuteRead = 0x003;
const int kPageReadWrite = 0x004;
const int kPageWriteCopy = 0x005;
const int kPageExecuteReadWrite = 0x006;
const int kPageExecuteWriteCopy = 0x007;

bool LessModuleName(const ProcessWorkingSet::ModuleStats& a,
                    const ProcessWorkingSet::ModuleStats& b) {
  return a.module_name < b.module_name;
}

}  // namespace


bool ProcessWorkingSet::Initialize(DWORD process_id) {
  ModuleAddressSpace modules;
  if (!CaptureModules(process_id, &modules))
    return false;

  const DWORD kProcessPermissions = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
  base::win::ScopedHandle process(
        ::OpenProcess(kProcessPermissions, FALSE, process_id));
  if (!process.IsValid()) {
    DWORD err = ::GetLastError();
    LOG(ERROR) << "OpenProcess failed: " << common::LogWe(err);
    return false;
  }

  ScopedWsPtr working_set;
  if (!CaptureWorkingSet(process.Get(), &working_set))
    return false;

  // The new stats we're building.
  ModuleStatsVector new_stats;

  // This maps from module name to index in the above vector.
  typedef std::map<std::wstring, size_t> NameToIndexMap;
  NameToIndexMap name_to_index;
  for (size_t i = 0; i < working_set->NumberOfEntries; ++i) {
    PSAPI_WORKING_SET_BLOCK entry = working_set->WorkingSetInfo[i];

    size_t address = entry.VirtualPage * kPageSize;
    ModuleAddressSpace::Range page_range(address, kPageSize);
    ModuleAddressSpace::RangeMap::const_iterator it =
        modules.FindContaining(page_range);

    Stats* stats = NULL;
    if (it == modules.end()) {
      stats = &non_module_stats_;
    } else {
      // Find the module with this name, or add it if it's missing.
      const std::wstring& module_name = it->second;
      NameToIndexMap::const_iterator it = name_to_index.find(module_name);
      if (it == name_to_index.end()) {
        // We haven't seen this module, add it to the end of the vector.
        name_to_index[module_name] = new_stats.size();
        new_stats.push_back(ModuleStats());

        ModuleStats* module_stats = &new_stats.back();
        module_stats->module_name = module_name;

        stats = module_stats;
      } else {
        stats = &new_stats[it->second];
      }
    }

    DCHECK(stats != NULL);

    total_stats_.pages++;
    stats->pages++;
    if (entry.Shared) {
      total_stats_.shareable_pages++;
      stats->shareable_pages++;
    }

    if (entry.ShareCount > 1) {
      total_stats_.shared_pages++;
      stats->shared_pages++;
    }

    if (entry.Protection & kPageReadWrite) {
      total_stats_.writable_pages++;
      stats->writable_pages++;
    } else if (entry.Protection & kPageExecute) {
      total_stats_.executable_pages++;
      stats->executable_pages++;
    } else if (entry.Protection & kPageReadOnly) {
      total_stats_.read_only_pages++;
      stats->read_only_pages++;
    }
  }

  std::sort(new_stats.begin(), new_stats.end(), LessModuleName);
  new_stats.swap(module_stats_);
  return true;
}

bool ProcessWorkingSet::CaptureWorkingSet(HANDLE process,
                                          ScopedWsPtr* working_set) {
  DCHECK(working_set != NULL);

  // Estimate the starting buffer size by the current WS size.
  PROCESS_MEMORY_COUNTERS counters = {};
  if (!::GetProcessMemoryInfo(process, &counters, sizeof(counters))) {
    DWORD err = ::GetLastError();
    LOG(ERROR) << "Unable to get process memory info: " << common::LogWe(err);
    return false;
  }

  scoped_ptr<PSAPI_WORKING_SET_INFORMATION> buffer;
  DWORD number_of_entries = counters.WorkingSetSize / kPageSize;
  int retries = 5;
  for (;;) {
    DWORD buffer_size = sizeof(PSAPI_WORKING_SET_INFORMATION) +
                        (number_of_entries * sizeof(PSAPI_WORKING_SET_BLOCK));

    // If we can't expand the buffer, don't leak the previous
    // contents or pass a NULL pointer to QueryWorkingSet.
    buffer.reset(reinterpret_cast<PSAPI_WORKING_SET_INFORMATION*>(
        new char[buffer_size]));
    if (!buffer.get()) {
      LOG(ERROR) << "Unable to allocate working set buffer.";
      return false;
    }
    // Zero the buffer as Gary Nebbet warns that undefined bits may not be set
    // in the Windows NT/2000 Native API Reference.
    memset(buffer.get(), 0, buffer_size);

    // Call the function once to get number of items.
    if (::QueryWorkingSet(process, buffer.get(), buffer_size))
      break;

    if (::GetLastError() != ERROR_BAD_LENGTH) {
      return false;
    }

    number_of_entries = static_cast<DWORD>(buffer->NumberOfEntries);

    // Maybe some entries are being added right now. Increase the buffer to
    // take that into account.
    number_of_entries = static_cast<DWORD>(number_of_entries * 1.25);

    if (--retries == 0) {
      LOG(ERROR) << "Out of retries to query working set.";
      return false;
    }
  }

  working_set->swap(buffer);
  return true;
}

bool ProcessWorkingSet::CaptureModules(DWORD process_id,
                                       ModuleAddressSpace* modules) {
  DCHECK(modules != NULL);

  base::win::ScopedHandle snap(
      ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id));
  if (!snap.IsValid()) {
    DWORD err = ::GetLastError();
    LOG(ERROR) << "CreateToolhelp32Snapshot failed: " << common::LogWe(err);
    return false;
  }

  MODULEENTRY32 module = { sizeof(module) };
  if (!::Module32First(snap.Get(), &module)) {
    DWORD err = ::GetLastError();
    LOG(ERROR) << "Module32First failed: " << common::LogWe(err);
    return false;
  }

  do {
    ModuleAddressSpace::Range range(
        reinterpret_cast<size_t>(module.modBaseAddr), module.modBaseSize);
    if (!modules->Insert(range, module.szExePath)) {
      LOG(ERROR) << "Module insertion failed, overlapping modules?";
      return false;
    }
  } while (::Module32Next(snap.Get(), &module));

  DWORD err = ::GetLastError();
  if (err != ERROR_NO_MORE_FILES) {
    LOG(ERROR) << "Module32Next failed: " << common::LogWe(err);
    return false;
  }

  return true;
}

}  // namespace wsdump
