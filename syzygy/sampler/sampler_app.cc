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

#include "syzygy/sampler/sampler_app.h"

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "syzygy/pe/pe_file.h"

namespace sampler {

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options] MODULE_PATH1 [MODULE_PATH2 ...]\n"
    "\n"
    "  A tool that polls running processes and profiles modules of interest.\n"
    "\n"
    "  The tool works by monitoring running processes. Any process that gets\n"
    "  through the optional PID filter will be inspected, and if any of the\n"
    "  specified modules are loaded in that process they will be profiled.\n"
    "\n"
    "Options:\n"
    "\n"
    "  blacklist-pids      If a list of PIDs is specified with --pids, this\n"
    "                      makes the list a blacklist of processes not to be\n"
    "                      monitored. Defaults to false, in which case the\n"
    "                      list is a whitelist.\n"
    "  pids=PID1,PID2,...  Specifies a list of PIDs. If specified these are\n"
    "                      used as a filter (by default a whitelist) for\n"
    "                      processes to be profiled. If not specified all\n"
    "                      processes will be potentially profiled.\n"
    "  output-dir=DIR      Specifies the output directory into which trace\n"
    "                      files will be written.\n"
    "\n";

}  // namespace

const char SamplerApp::kBlacklistPids[] = "blacklist-pids";
const char SamplerApp::kPids[] = "pids";
const char SamplerApp::kOutputDir[] = "output-dir";

SamplerApp::SamplerApp()
    : common::AppImplBase("Sampler"),
      blacklist_pids_(true) {
}

bool SamplerApp::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  if (command_line->HasSwitch("help"))
    return PrintUsage(command_line->GetProgram(), "");

  // By default we set up an empty PID blacklist. This means that all PIDs
  // will be profiled.
  if (command_line->HasSwitch(kPids)) {
    // If PIDs have been specified then parse them.
    if (!ParsePids(command_line->GetSwitchValueASCII(kPids)))
      return PrintUsage(command_line->GetProgram(), "");

    blacklist_pids_ = command_line->HasSwitch(kBlacklistPids);
  }

  const CommandLine::StringVector& args = command_line->GetArgs();
  if (args.size() == 0) {
    return PrintUsage(command_line->GetProgram(),
                      "Must specify at least one module to profile.");
  }

  // Parse the list of modules to profile.
  for (size_t i = 0; i < args.size(); ++i) {
    ModuleSignature sig = {};
    if (!GetModuleSignature(base::FilePath(args[i]), &sig))
      return PrintUsage(command_line->GetProgram(), "");
    module_sigs_.insert(sig);
  }

  return true;
}

int SamplerApp::Run() {
  // TODO(chrisha): Implement me!
  LOG(ERROR) << "Not implemented yet!";
  return 1;
}

bool SamplerApp::PrintUsage(const base::FilePath& program,
                            const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());

  return false;
}

bool SamplerApp::ParsePids(const std::string& pids) {
  std::vector<std::string> split;
  base::SplitString(pids, ',', &split);

  for (size_t i = 0; i < split.size(); ++i) {
    std::string s;
    ::TrimWhitespace(split[i], TRIM_ALL, &s);

    // Skip empty strings.
    if (s.empty())
      continue;

    uint32 pid = 0;
    if (!base::StringToUint(s, &pid)) {
      LOG(ERROR) << "Unable to parse \"" << s << "\" as a PID.";
      return false;
    }
    pids_.insert(pid);
  }

  if (pids_.empty()) {
    LOG(ERROR) << "--" << kPids << " must not be empty.";
    return false;
  }

  return true;
}

bool SamplerApp::GetModuleSignature(
    const base::FilePath& module, ModuleSignature* sig) {
  DCHECK(sig != NULL);

  pe::PEFile pe_file;
  if (!pe_file.Init(module))
    return false;

  pe::PEFile::Signature pe_sig;
  pe_file.GetSignature(&pe_sig);

  sig->size = pe_sig.module_size;
  sig->time_date_stamp = pe_sig.module_time_date_stamp;
  sig->checksum = pe_sig.module_checksum;

  return true;
}

bool SamplerApp::ModuleSignature::operator<(const ModuleSignature& rhs) const {
  if (size != rhs.size)
    return size < rhs.size;
  if (time_date_stamp != rhs.time_date_stamp)
    return time_date_stamp < rhs.time_date_stamp;
  return checksum < rhs.checksum;
}

}  // namespace sampler
