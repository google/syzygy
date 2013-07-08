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
#ifndef SYZYGY_SAMPLER_SAMPLER_APP_H_
#define SYZYGY_SAMPLER_SAMPLER_APP_H_

#include <set>

#include "base/files/file_path.h"
#include "syzygy/common/application.h"

namespace sampler {

// The application class that takes care of running a profiling sampler. This
// works by polling running processes and attaching a
// base::win::SamplingProfiler instance to every module of interest. The output
// is then shuttled to trace data files.
class SamplerApp : public common::AppImplBase {
 public:
  SamplerApp();

  // @name Implementation of the AppImplbase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

  // @name Command-line switches.
  // @{
  static const char kBlacklistPids[];
  static const char kPids[];
  static const char kOutputDir[];
  // @}

 protected:
  struct ModuleSignature;

  // Helper function for printing a usage statement.
  // @param program The path to the executable.
  // @param message An optional message that will precede the usage statement.
  // @returns false.
  bool PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);

  // Parses a comma-seperated list of PIDs (non-negative integers) and
  // populates pids_.
  // @param pids A comma-separated list of PIDs.
  // @returns true on success, false otherwise.
  bool ParsePids(const std::string& pids);

  // Initializes a ModuleSignature given a path. Logs an error on failure.
  // @param module The path to the module.
  // @param sig The signature object to be initialized.
  // @returns true on success, false otherwise.
  static bool GetModuleSignature(
      const base::FilePath& module, ModuleSignature* sig);

  // Used for storing a set of PIDs. This plays the role of a whitelist or a
  // blacklist for selecting processes of interest.
  typedef std::set<DWORD> PidSet;
  PidSet pids_;

  // If this is true then the PidSet plays the role of a blacklist. If false it
  // is a whitelist.
  bool blacklist_pids_;

  // List of modules of interest. Any instances of these modules that are
  // loaded in processes of interest (those that get through our process
  // filter) will be profiled.
  typedef std::set<ModuleSignature> ModuleSignatureSet;
  ModuleSignatureSet module_sigs_;
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
