// Copyright 2013 Google Inc. All Rights Reserved.
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
// Defines SampledModuleCache. This is container for storing profiling
// information for many modules that are being profiled across many processes.
// It is intended to be used by a polling monitor which periodically looks for
// new modules to be profiled, and detects when old modules are no longer
// loaded or when processes have terminated.
//
// Because of the polling nature the cache contains mechanisms for doing mark
// and sweep garbage collection. It is intended to be used as follows:
//
// // All modules will be profiled with the same bucket size.
// SampledModuleCache cache(log2_bucket_size);
//
// // Set up a callback that will be invoked when profiling is done for a
// // module.
// cache.set_dead_module_callback(some_callback);
//
// while (... we wish the profiler to continue running...) {
//   // Mark all currently profiling modules as dead.
//   cache.MarkAllModulesDead();
//
//   for (... each module we want to profile ...) {
//     // We have a |handle| to the process to be profiled and the address of
//     // the |module| to be processed as an HMODULE. The module may already be
//     // in the process of being profiled, but this will simply mark it as
//     // still being alived and eligible for continued profiling.
//     cache.AddModule(handle, module);
//   }
//
//   // Clean up any modules that haven't been added (or re-added and marked as
//   // alive). This invokes our callback with the gathered profile data.
//   cache.RemoveDeadModules();
// }

#ifndef SYZYGY_SAMPLER_SAMPLED_MODULE_CACHE_H_
#define SYZYGY_SAMPLER_SAMPLED_MODULE_CACHE_H_

#include <map>

#include "base/basictypes.h"
#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/win/sampling_profiler.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/application.h"
#include "syzygy/trace/common/clock.h"

namespace sampler {

class SampledModuleCache {
 public:
  // Forward declarations. See below for details.
  class Process;
  class Module;

  typedef std::map<WORD, Process*> ProcessMap;

  // This is the callback that is used to indicate that a module has been
  // unloaded and/or we have stopped profiling it (from our point of view, it is
  // dead). It is up to the callback to deal with the sample data.
  typedef base::Callback<void(const Module* module)> DeadModuleCallback;

  // Constructor.
  // @param log2_bucket_size The number of bits in the bucket size to be used
  //     by the sampling profiler. This must be in the range 2-31, for bucket
  //     sizes of 4 bytes to 2 gigabytes. See base/win/sampling_profiler.h
  //     for more details.
  explicit SampledModuleCache(size_t log2_bucket_size);

  // Destructor.
  ~SampledModuleCache();

  // Sets the callback that is invoked as 'dead' modules are removed from the
  // cache.
  // @param callback The callback to be invoked. This may be a default
  //     constructed (empty) callback to indicate that no callback is to be
  //     invoked.
  void set_dead_module_callback(const DeadModuleCallback& callback) {
    dead_module_callback_ = callback;
  }

  // @name Accessors.
  // @{
  const ProcessMap& processes() const { return processes_; }
  size_t log2_bucket_size() const { return log2_bucket_size_; }
  const DeadModuleCallback& dead_module_callback() const {
    return dead_module_callback_;
  }
  // @}

  // Starts profiling the given module in the given process. If the process and
  // module are already being profiled this simply marks them as still alive.
  // @param process A handle to the process. This handle will be duplicated
  //     and the cache will take responsibility for lifetime management of the
  //     copy.
  // @param module The module to be profiled.
  // @returns true if the process and module were added and profiling was
  //     successfully started.
  bool AddModule(HANDLE process, HMODULE module);

  // Marks all processes and modules as dead.
  void MarkAllModulesDead();

  // Cleans up no longer running modules and processes. Prior to removal of a
  // module the dead module callback will be invoked, if set.
  void RemoveDeadModules();

 private:
  // The set of all processes, and modules within them, that are currently
  // begin profiled.
  ProcessMap processes_;

  // The bucket size to be used by all profiler instances created by this
  // cache.
  size_t log2_bucket_size_;

  // The callback that is being invoked when dead modules are removed, or when
  // the entire cache is being destroyed.
  DeadModuleCallback dead_module_callback_;

  DISALLOW_COPY_AND_ASSIGN(SampledModuleCache);
};

// A Process tracks a process containing one or more modules that are
// currently being profiled. Processes are polled so there is no guarantee
// that a tracked process is still running.
class SampledModuleCache::Process {
 public:
  typedef std::map<HMODULE, Module*> ModuleMap;

  // Constructor. Creates a sampled process for the given process handle.
  // @param process The handle to the process to be profiled. Ownership of this
  //     handle is transferred to this object.
  // @param pid The PID of the process.
  Process(HANDLE process, DWORD pid);

  // Destructor.
  ~Process();

  // @name Accessors.
  // @{
  HANDLE process() const { return process_.Get(); }
  DWORD pid() const { return pid_; }
  ModuleMap& modules() { return modules_; }
  const ModuleMap& modules() const { return modules_; }
  // @}

  // Adds the provided module to the set of modules that are being profiled in
  // this process. Only returns true if the module is able to be successfully
  // queried and the sampling profiler is started.
  // @param module The module to be added.
  // @param log2_bucket_size The number of bits in the bucket size to be used
  //     by the sampling profiler. This must be in the range 2-31, for bucket
  //     sizes of 4 bytes to 2 gigabytes. See base/win/sampling_profiler.h
  //     for more details.
  // @returns true on success, false otherwise.
  bool AddModule(HMODULE module, size_t log2_bucket_size);

 protected:
  friend class SampledModuleCache;

  // @name Mark and sweep accessors.  These are used internally by the parent
  //     SampledModuleCache.
  // @{
  bool alive() const { return alive_; }
  void MarkAlive() { alive_ = true; }
  void MarkDead();
  // @}

  // Cleans up no longer running modules.
  // @param callback The callback to be invoked on each module just prior to
  //     removing it. May be empty.
  void RemoveDeadModules(DeadModuleCallback callback);

 private:
  friend class SampledModuleCacheTest;  // Testing seam.

  // A scoped handle to the running process.
  base::win::ScopedHandle process_;

  // The process ID of the process. This is used as the key for a
  // Process.
  DWORD pid_;

  // The set of all modules that are currently being profiled.
  ModuleMap modules_;

  // This is used for cleaning up no longer running processes using a mark and
  // sweep technique. The containing SampledModuleCache enforces the invariant
  // that alive_ is false if and only if all of our child modules are dead.
  bool alive_;

  DISALLOW_COPY_AND_ASSIGN(SampledModuleCache::Process);
};

// A Module tracks a module (belonging to a Process) that is currently
// being profiled by an instance of a base::win::SamplingProfiler. Modules are
// polled so there is no guarantee that a tracked module is still loaded, nor
// if its parent process is still running.
class SampledModuleCache::Module {
 public:
  // Constructor.
  // @param process The process to which this module belongs.
  // @param module The handle to the module to be profiled.
  // @param log2_bucket_size The number of bits in the bucket size to be used
  //     by the sampling profiler. This must be in the range 2-31, for bucket
  //     sizes of 4 bytes to 2 gigabytes. See base/win/sampling_profiler.h
  //     for more details.
  Module(Process* process, HMODULE module, size_t log2_bucket_size);

 protected:
  friend class SampledModuleCache;

  // @name Mark and sweep accessors. These are used internally by the parent
  //     SampledModuleCache.
  // @{
  bool alive() const { return alive_; }
  void MarkAlive() { alive_ = true; }
  void MarkDead() { alive_ = false; }
  // @}

  // Initializes this module by reaching into the other process and getting
  // information about it.
  // @returns true on success, false otherwise.
  bool Init();

  // Starts the sampling profiler.
  // @returns true on success, false otherwise.
  bool Start() { return profiler_.Start(); }

  // Stops the sampling profiler.
  // @returns true on success, false otherwise.
  bool Stop() { return profiler_.Stop(); }

 private:
  friend class SampledModuleCacheTest;  // Testing seam.

  // A pointer to the metadata about the process in which this module is loaded.
  Process* process_;

  // A handle to the module. This is simply a pointer to the base address of the
  // module in the other process' address space. Modules are stored in
  // a set in their parent Process, keyed off the module handle.
  HMODULE module_;

  // Information that uniquely identifies the module. This information is needed
  // when we output the TraceSampleData record to the trace file.
  size_t module_size_;
  uint32 module_checksum_;
  uint32 module_time_date_stamp_;

  // Information about the portion of the module being profiled. These are
  // addresses in the remove module and minimally highlight the .text section
  // of the image.
  const void* buckets_begin_;
  const void* buckets_end_;
  size_t log2_bucket_size_;

  // The time when we started profiling this module, as reported by RDTSC.
  uint64 profiling_start_time_;

  // The sampling profiler instance that is profiling this module.
  base::win::SamplingProfiler profiler_;

  // This is used for cleaning up no longer loaded modules using a mark and
  // sweep technique.
  bool alive_;

  DISALLOW_COPY_AND_ASSIGN(SampledModuleCache::Module);
};

}  // namespace sampler

#endif  // SYZYGY_SAMPLER_SAMPLED_MODULE_CACHE_H_
