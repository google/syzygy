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
// Module cache implementation.
#include "sawbuck/sym_util/module_cache.h"

namespace sym_util {

// The empty module load state.
ModuleCache::ModuleLoadState ModuleCache::empty_;


ModuleCache::ModuleCache() : next_module_load_state_id_(0) {
}

void ModuleCache::ModuleLoaded(ProcessId pid,
                               const base::Time& time,
                               const ModuleInformation& module) {
  ModuleStateKey key(pid, time);

  // Find the state we have for this process.
  ModuleLoadState state(GetStateForProcess(key));

  // Add the new module.
  state.insert(GetModuleId(module));

  // And store it.
  SetProcessState(key, GetModuleLoadStateId(state));
}

void ModuleCache::ModuleUnloaded(ProcessId pid,
                                 const base::Time& time,
                                 const ModuleInformation& module) {
  ModuleStateKey key(pid, time);

  // Find the state we have for this process.
  ModuleLoadState state(GetStateForProcess(key));

  // Remove the module.
  state.erase(GetModuleId(module));

  // And store it.
  SetProcessState(key, GetModuleLoadStateId(state));
}

bool ModuleCache::GetProcessModuleState(
    ProcessId pid, const base::Time& time,
    std::vector<ModuleInformation>* modules) {
  modules->clear();

  ModuleStateKey key(pid, time);
  // Find the state we have for this process.
  const ModuleLoadState& state(GetStateForProcess(key));
  if (state.empty())
    return false;

  ModuleLoadState::const_iterator it(state.begin());
  ModuleLoadState::const_iterator end(state.end());
  for (; it != end; ++it)
    modules->push_back(GetModule(*it));

  return true;
}

ModuleCache::ModuleLoadStateId ModuleCache::GetStateId(
    ProcessId pid, const base::Time& start_time) {
  return GetStateIdForProcess(ModuleStateKey(pid, start_time));
}

ModuleCache::ModuleId ModuleCache::GetModuleId(
    const ModuleInformation& module_info) {
  ModuleInfoMap::iterator it(module_ids_.find(module_info));

  if (it != module_ids_.end())
    return it->second;

  ModuleId module_id = modules_.size();
  module_ids_.insert(std::make_pair(module_info, module_id));
  modules_.push_back(module_info);

  return module_id;
}

const ModuleInformation& ModuleCache::GetModule(ModuleId id) {
  return modules_[id];
}

ModuleCache::ModuleLoadStateId ModuleCache::GetModuleLoadStateId(
    const ModuleLoadState& state) {
  ModuleLoadStateMap::iterator it(module_load_state_ids_.find(state));

  if (it != module_load_state_ids_.end())
    return it->second;

  ModuleLoadStateId id = next_module_load_state_id_++;
  module_load_state_ids_.insert(std::make_pair(state, id));
  module_load_states_.push_back(state);

  return id;
}

const ModuleCache::ModuleLoadState& ModuleCache::GetModuleLoadState(
    ModuleLoadStateId id) {
  return module_load_states_[id];
}

ModuleCache::ModuleLoadStateId ModuleCache::GetStateIdForProcess(
    const ModuleStateKey& key) {
  ProcessLoadStateMap::iterator it(process_states_.upper_bound(key));
  // Back up one if we can.
  if (it != process_states_.begin())
    --it;

  // If we hit on the right process, we found the nearest info we have.
  if (it != process_states_.end() && it->first.pid_ == key.pid_)
    return it->second;

  return kInvalidModuleLoadState;
}

const ModuleCache::ModuleLoadState& ModuleCache::GetStateForProcess(
    const ModuleStateKey& key) {
  ModuleLoadStateId id = GetStateIdForProcess(key);

  if (id == kInvalidModuleLoadState)
    return empty_;

  return GetModuleLoadState(id);
}

void ModuleCache::SetProcessState(const ModuleStateKey& key,
                                  ModuleLoadStateId id) {
  ProcessLoadStateMap::iterator it(process_states_.upper_bound(key));
  // Back up one if we can.
  if (it != process_states_.begin())
    --it;

  // Do we need to insert a new entry?
  if (it == process_states_.end() || it->first != key) {
    process_states_.insert(std::make_pair(key, id));
  } else {  // it->first == key
    it->second = id;
  }
}

}  // namespace sym_util
