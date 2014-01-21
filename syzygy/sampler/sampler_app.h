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
// Declares the Sampler applications. This is an application for sampling
// profiling modules. It can profile multiple uninstrumented modules across
// multiple processes.
#ifndef SYZYGY_SAMPLER_SAMPLER_APP_H_
#define SYZYGY_SAMPLER_SAMPLER_APP_H_

#include <set>

#include "base/time.h"
#include "base/files/file_path.h"
#include "syzygy/common/application.h"
#include "syzygy/sampler/sampled_module_cache.h"

namespace sampler {

// The application class that takes care of running a profiling sampler. This
// works by polling running processes and attaching a SamplingProfiler instance
// to every module of interest. The output is then shuttled to trace data files.
class SamplerApp : public common::AppImplBase {
 public:
  SamplerApp();
  ~SamplerApp();

  // @name Implementation of the AppImplbase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

  // @name Command-line switches.
  // @{
  static const char kBlacklistPids[];
  static const char kBucketSize[];
  static const char kPids[];
  static const char kSamplingInterval[];
  static const char kOutputDir[];
  // @}

  // @name Default command-line values.
  // @{
  static const size_t kDefaultLog2BucketSize;
  // @}

  // These are exposed for use by anonymous helper functions.
  struct ModuleSignature;
  typedef std::set<ModuleSignature> ModuleSignatureSet;

 protected:
  // Inner implementation of Run().
  int RunImpl();

  // @name Unittesting seams.
  // @{
  virtual void OnStartProfiling(const SampledModuleCache::Module* module) { }
  virtual void OnStopProfiling(const SampledModuleCache::Module* module) { }
  // @}

  // Helper function for printing a usage statement.
  // @param program The path to the executable.
  // @param message An optional message that will precede the usage statement.
  // @returns false.
  bool PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);

  // Parses a comma-separated list of PIDs (non-negative integers) and
  // populates pids_.
  // @param pids A comma-separated list of PIDs.
  // @returns true on success, false otherwise.
  bool ParsePids(const std::string& pids);

  // The callback that is invoked for modules once we have finished profiling
  // them.
  // @param module The module that has just finished profiling.
  void OnDeadModule(const SampledModuleCache::Module* module);

  // Initializes a ModuleSignature given a path. Logs an error on failure.
  // @param module The path to the module.
  // @param sig The signature object to be initialized.
  // @returns true on success, false otherwise.
  static bool GetModuleSignature(
      const base::FilePath& module, ModuleSignature* sig);

  // Used for handling console messages.
  // @param ctrl_type The type of the console control message.
  // @returns TRUE if the signal was handled, FALSE otherwise.
  static BOOL WINAPI OnConsoleCtrl(DWORD ctrl_type);

  // @name Accessors/mutators for running_.
  // @{
  bool running();
  void set_running(bool running);
  // @}

  // Used for storing a set of PIDs. This plays the role of a whitelist or a
  // blacklist for selecting processes of interest.
  typedef std::set<DWORD> PidSet;
  PidSet pids_;

  // If this is true then the PidSet plays the role of a blacklist. If false it
  // is a whitelist.
  bool blacklist_pids_;

  // Sampling profiler parameters.
  size_t log2_bucket_size_;
  base::TimeDelta sampling_interval_;

  // The output directory where trace files will be written.
  base::FilePath output_dir_;

  // List of modules of interest. Any instances of these modules that are
  // loaded in processes of interest (those that get through our process
  // filter) will be profiled.
  ModuleSignatureSet module_sigs_;

  // Used to indicate whether or not the sampler should continue running.
  base::Lock lock_;
  bool running_;  // Under lock.

  // @name Internal state and calculations.
  // @{
  uint64 sampling_interval_in_cycles_;
  // @}

  // Only one instance of this class can register for console control messages,
  // on a first-come first-serve basis.
  static base::Lock console_ctrl_lock_;
  static SamplerApp* console_ctrl_owner_;  // Under console_ctrl_lock_.
};

// Used for storing a bare minimum signature of a module.
struct SamplerApp::ModuleSignature {
  uint32 size;
  uint32 time_date_stamp;
  uint32 checksum;

  // Comparison operator
  bool operator<(const ModuleSignature& rhs) const;
};

}  // namespace sampler

#endif  // SYZYGY_SAMPLER_SAMPLER_APP_H_
