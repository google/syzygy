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
#include "base/json/string_escape.h"
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

const char kUsage[] =
"Usage: wsdump [--process-name=<process_re>]\n"
"\n"
"    Captures and outputs working set statistics for all processes,\n"
"    or only for processess whose executable name matches <process_re>.\n"
"\n"
"    The output is JSON encoded array, where each element of the array\n"
"    is a dictionary describing a process. Each process has the following\n"
"    items:\n"
"      * exe_file - the process' executable file, e.g. \"chrome.exe\".\n"
"      * pid - the process ID.\n"
"      * parent_pid - the parent process ID.\n"
"      * modules - an array of dictionaries, one for each module in the\n"
"        process working set.\n"
"    Each module has the following keys:\n"
"      * module_name - the module file name, e.g. \"C:\\temp\\xyz.dll\"\n"
"      * pages - total number of pages from this module in the working set.\n"
"      * shareable_pages - shareable pages in the working set.\n"
"      * shared_pages - shared pages in the working set.\n"
"      * read_only_pages - read-only pages in the working set.\n"
"      * writable_pages - writable pages in the working set.\n"
"      * executable_pages - executable pages in the working set.\n"
"\n"
"Example Output:\n"
"[\n"
"  {\n"
"    \"exe_file\": \"devenv.exe\",\n"
"    \"pid\": 5772,\n"
"    \"parent_pid\": 3804,\n"
"    \"modules\": [\n"
"      {\n"
"        \"module_name\": \"Total\",\n"
"        \"pages\": 34145,\n"
"        \"shareable_pages\": 10515,\n"
"        \"shared_pages\": 4847,\n"
"        \"read_only_pages\": 1951,\n"
"        \"writable_pages\": 23235,\n"
"        \"executable_pages\": 8959\n"
"      },\n"
"      {\n"
" ... \n";

int Usage() {
  std::cout << kUsage;
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

void OutputKeyValue(const char* key,
                    const std::wstring& value,
                    int indent,
                    bool trailing_comma) {
  std::cout << std::string(indent, ' ')
      << base::GetDoubleQuotedJson(key) << ": "
      << base::GetDoubleQuotedJson(value)
      << (trailing_comma ? "," : "") << "\n";
}

template <class Streamable>
void OutputKeyValue(const char* key,
                    const Streamable& value,
                    int indent,
                    bool trailing_comma) {
  std::cout << std::string(indent, ' ')
      << base::GetDoubleQuotedJson(key) << ": "
      << value
      << (trailing_comma ? "," : "") << "\n";
}

void OutputModule(const std::wstring& module_name,
                  const ProcessWorkingSet::Stats& stats,
                  bool trailing_comma) {
  std::cout << "      {\n";
  OutputKeyValue("module_name", module_name, 8, true);
  OutputKeyValue("pages", stats.pages, 8, true);
  OutputKeyValue("shareable_pages", stats.shareable_pages, 8, true);
  OutputKeyValue("shared_pages", stats.shared_pages, 8, true);
  OutputKeyValue("read_only_pages", stats.read_only_pages, 8, true);
  OutputKeyValue("writable_pages", stats.writable_pages, 8, true);
  OutputKeyValue("executable_pages", stats.executable_pages, 8, false);
  std::cout << "      }" << (trailing_comma ? "," : "") << "\n";
}

void OutputProcessInfo(const ProcessInfo& info, bool trailing_comma) {
  std::cout << "  {\n";
  OutputKeyValue("exe_file", info.exe_file, 4, true);
  OutputKeyValue("pid", info.pid, 4, true);
  OutputKeyValue("parent_pid", info.parent_pid, 4, true);
  std::cout << "    \"modules\": [\n";

  OutputModule(L"Total", info.ws.total_stats(), true);
  ProcessWorkingSet::ModuleStatsVector::const_iterator it =
      info.ws.module_stats().begin();
  ProcessWorkingSet::ModuleStatsVector::const_iterator end =
      info.ws.module_stats().end();
  for (; it != end; ++it)
    OutputModule(it->module_name, *it, it + 1 != end);

  std::cout << "    ]\n";
  std::cout << "  }" << (trailing_comma ? "," : "") << "\n";
}

} // namespace

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

  std::cout << "[\n";
  WorkingSets::const_iterator it = working_sets.begin();
  for (; it != working_sets.end(); ++it) {
    WorkingSets::const_iterator next = it;
    ++next;
    OutputProcessInfo(*it, next != working_sets.end());
  }
  std::cout << "]\n";

  return 0;
}
