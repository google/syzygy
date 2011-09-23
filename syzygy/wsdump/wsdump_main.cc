// Copyright 2011 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <iostream>
#include <list>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/process_util.h"
#include "base/utf_string_conversions.h"
#include "pcrecpp.h"  // NOLINT
#include "syzygy/wsdump/process_working_set.h"

namespace {

class RegexpProcessFilter: public base::ProcessFilter {
 public:
  RegexpProcessFilter();

  bool Initialize(const std::string& regexpr);

  virtual bool Includes(const base::ProcessEntry& entry) const OVERRIDE;

 private:
  pcrecpp::RE expr_;
};

RegexpProcessFilter::RegexpProcessFilter() : expr_("") {
}

bool RegexpProcessFilter::Initialize(const std::string& regexpr) {
  pcrecpp::RE_Options options;
  options.set_utf8(true);
  options.set_caseless(true);
  pcrecpp::RE new_expr(regexpr, options);

  if (!new_expr.error().empty()) {
    LOG(ERROR) << "Failed to initialize regular expression, error: "
        << new_expr.error();
    return false;
  }

  expr_ = new_expr;
  DCHECK_EQ("", new_expr.error());

  return true;
}

bool RegexpProcessFilter::Includes(const base::ProcessEntry& entry) const {
  return expr_.PartialMatch(WideToUTF8(entry.exe_file()));
}

} // namespace

static const char kUsage[] =
"Usage: wsdump [--process-name=<process_re>]\n"
"\n"
"    Captures and outputs working set statistics for all processes,\n"
"    or only for processess whose executable name matches <process_re>.\n"
"\n"
"    The output is tab-separated, where a process heading starts a line with\n"
"    an executable name, followed by the process PID and parent PID.\n"
"    Following a process heading is a tab-prefixed line for each module that\n"
"    appear in its working set, where the line has the following columns\n"
"      * Module path.\n"
"      * Total number of pages.\n"
"      * Number of shareable pages.\n"
"      * Number of shared pages.\n"
"      * Number of read-only (non-executable) pages.\n"
"      * Number of writable pages.\n"
"      * Number of executable pages.\n"
"\n"
"Example output:\n"
"\n"
"notepad++.exe  4648  3600\n"
"  Total:  4402  2694  2377  4402  2694  2377  963  1714 1725\n"
"  C:\\PROGRA~2\\Sophos\\SOPHOS~1\\SOPHOS~1.DLL  3  3  3 3  3  3  1  0  2\n"
"  C:\\Windows\\SysWOW64\\ntdll.dll  84  78  78  84  78 78  1  5  78\n";

static int Usage() {
  std::cout << kUsage;
  return 1;
}

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(L"", logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
      logging::DONT_LOCK_LOG_FILE, logging::APPEND_TO_OLD_LOG_FILE,
      logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help") || !cmd_line->args().empty()) {
    return Usage();
  }

  // If the process-name is empty or missing we match all processes.
  std::string process_re = cmd_line->GetSwitchValueASCII("process-name");
  RegexpProcessFilter filter;
  if (!filter.Initialize(process_re)) {
    LOG(ERROR) << "Incorrect process filter regular expression.";
    return 1;
  }

  struct ProcessInfo {
    ProcessInfo() : pid(0), parent_pid(0) {
    }

    std::wstring exe_file;
    base::ProcessId pid;
    base::ProcessId parent_pid;
    ProcessWorkingSet ws;
  };
  typedef std::list<ProcessInfo> WorkingSets;
  WorkingSets working_sets;

  const base::ProcessEntry* entry = NULL;
  base::ProcessIterator process_iterator(&filter);
  while (entry = process_iterator.NextProcessEntry()) {
    working_sets.push_back(ProcessInfo());
    ProcessInfo& info = working_sets.back();
    if (info.ws.Initialize(entry->pid())) {
      info.exe_file = entry->exe_file();
      info.pid = entry->pid();
      info.parent_pid = entry->parent_pid();
    } else {
      LOG(ERROR) << "Unable to capture working set information for pid: "
          << entry->pid();
      working_sets.pop_back();
    }
  }

  WorkingSets::const_iterator it = working_sets.begin();
  for (; it != working_sets.end(); ++it) {
    std::cout << it->exe_file << "\t"
        << it->pid << "\t"
        << it->parent_pid << std::endl;

    const ProcessWorkingSet& ws = it->ws;
    std::cout << "\tTotal: "
        << "\t" << ws.total_stats().pages
        << "\t" << ws.total_stats().shareable_pages
        << "\t" << ws.total_stats().shared_pages
        << "\t" << ws.total_stats().pages
        << "\t" << ws.total_stats().shareable_pages
        << "\t" << ws.total_stats().shared_pages
        << "\t" << ws.total_stats().read_only_pages
        << "\t" << ws.total_stats().writable_pages
        << "\t" << ws.total_stats().executable_pages << std::endl;

    ProcessWorkingSet::ModuleStatsVector::const_iterator jt =
        ws.module_stats().begin();
    for (; jt != ws.module_stats().end(); ++jt) {
      std::cout << "\t" << jt->module_name
          << "\t" << jt->pages
          << "\t" << jt->shareable_pages
          << "\t" << jt->shared_pages
          << "\t" << jt->pages
          << "\t" << jt->shareable_pages
          << "\t" << jt->shared_pages
          << "\t" << jt->read_only_pages
          << "\t" << jt->writable_pages
          << "\t" << jt->executable_pages << std::endl;
    }
  }

  return 1;
}
