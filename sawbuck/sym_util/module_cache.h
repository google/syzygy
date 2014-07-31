// Copyright 2009 Google Inc.
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
// Module cache declaration.
#ifndef SAWBUCK_SYM_UTIL_MODULE_CACHE_H_
#define SAWBUCK_SYM_UTIL_MODULE_CACHE_H_

#include "base/time/time.h"
#include <map>
#include <set>
#include <string>
#include <vector>
#include "sawbuck/sym_util/types.h"

namespace sym_util {

// Keeps a cache of the module load state of a set of processes over time.
// Allows looking up and enumerating the module state of a process at a given
// point in time, as well as inexpensively check whether the module load
// state of a process has changed from one time point to another.
class ModuleCache {
 public:
  ModuleCache();

  // @p module loaded into @p pid at @p time.
  void ModuleLoaded(ProcessId pid,
                    const base::Time& time,
                    const ModuleInformation& module);
  // @p module unloaded from @p pid at @p time.
  void ModuleUnloaded(ProcessId pid,
                      const base::Time& time,
                      const ModuleInformation& module);

  // Retrieve the module state for process @p pid at @p time.
  bool GetProcessModuleState(ProcessId pid,
                             const base::Time& time,
                             std::vector<ModuleInformation>* modules);

  // Returns an arbitrary ID that's guaranteed to be different for any
  // two process load states - e.g. if GetProcessModuleState(pid, time, ...)
  // were to return different sets of modules for two values of {pid, time},
  // this function would return different IDs for both.
  // This function _may_ return the same ID for e.g. two different {pid, time}
  // pairs, if it so happens that the module load state for the processes
  // referred is identical at the times indicated.
  typedef size_t ModuleLoadStateId;
  ModuleLoadStateId GetStateId(ProcessId pid,
                               const base::Time& start_time);

 private:
  // Since the same module occurs loaded at the same address
  // quite a lot, we compress our dataset by mapping a module
  // info to an int.
  typedef size_t ModuleId;
  typedef std::map<ModuleInformation, ModuleId> ModuleInfoMap;
  // Maps from module info to its id.
  ModuleInfoMap module_ids_;
  // Maps from an id to the module information.
  std::vector<ModuleInformation> modules_;

  ModuleId GetModuleId(const ModuleInformation& module_info);
  const ModuleInformation& GetModule(ModuleId id);

  // The module load state of any process at any given time is
  // encoded as a set of module ids. And since we tend to have
  // multiple occurrences of the same module load state, e.g. when
  // you have multiple instances of the same executable running, we
  // encode entire module load states into an integer as well.
  typedef std::set<ModuleId> ModuleLoadState;
  typedef std::map<ModuleLoadState, ModuleLoadStateId> ModuleLoadStateMap;
  // Maps from module load state to id.
  ModuleLoadStateMap module_load_state_ids_;
  // Maps from id to module load state.
  std::vector<ModuleLoadState> module_load_states_;
  ModuleId next_module_load_state_id_;

  ModuleLoadStateId GetModuleLoadStateId(const ModuleLoadState& state);
  const ModuleLoadState& GetModuleLoadState(ModuleLoadStateId id);

  struct ModuleStateKey {
    ModuleStateKey(ProcessId pid, const base::Time& time)
        : pid_(pid), time_(time) {
    }

    bool operator < (const ModuleStateKey& o) const {
      if (pid_ < o.pid_)
        return true;
      else if (pid_ == o.pid_)
        return time_ < o.time_;
      return false;
    }

    bool operator == (const ModuleStateKey& o) const {
      return pid_ == o.pid_ && time_ == o.time_;
    }

    bool operator != (const ModuleStateKey& o) const {
      return !operator == (o);
    }

    ProcessId pid_;
    base::Time time_;
  };

  // Retrieves the module load state id for a process at a time.
  ModuleLoadStateId GetStateIdForProcess(const ModuleStateKey& key);
  // Set the module load state for a process at a time.
  void SetProcessState(const ModuleStateKey& key, ModuleLoadStateId id);

  // Retrieves the module load state for a process at a time.
  const ModuleLoadState& GetStateForProcess(const ModuleStateKey& key);

  // Maps from {pid, time} -> load state id.
  typedef std::map<ModuleStateKey, ModuleLoadStateId> ProcessLoadStateMap;
  ProcessLoadStateMap process_states_;

  static const ModuleLoadStateId kInvalidModuleLoadState = -1;
  static ModuleLoadState empty_;
};

}  // namespace sym_util

#endif  // SAWBUCK_SYM_UTIL_MODULE_CACHE_H_
