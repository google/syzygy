// Copyright 2011 Google Inc.
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
// Class encapsulating extraction and listing basic info on configuration.
#include "sawdust/tracer/system_info.h"

#include <string>
#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/sys_info.h"
#include "base/utf_string_conversions.h"

const char SystemInfoExtractor::kHeaderMem[] = "Physical memory";
const char SystemInfoExtractor::kHeaderSysName[] = "Operating system";
const char SystemInfoExtractor::kHeaderSysInfo[] = "Native system info";
const char SystemInfoExtractor::kHeaderSysInfo2[] = "System info";
const char SystemInfoExtractor::kHeaderPageSize[] = "Page size";
const char SystemInfoExtractor::kHeaderProcs[] = "Number of processors";
const char SystemInfoExtractor::kHeaderProcRev[] = "Processor revision";
const char SystemInfoExtractor::kHeaderProcMask[] = "Active processor mask";

// Formats data into a string and stuff it into the out string. All done on
// char-specialized data.
void SystemInfoExtractor::Initialize(bool include_env_variables) {
  std::string out_data_string;
  out_data_string.reserve(2048);

  base::StringAppendF(&out_data_string, "%s:\t%I64u\n", kHeaderMem,
                      base::SysInfo::AmountOfPhysicalMemory());

  base::StringAppendF(&out_data_string, "%s:\t%s version %s\n", kHeaderSysName,
                      base::SysInfo::OperatingSystemName().c_str(),
                      base::SysInfo::OperatingSystemVersion().c_str());

  base::StringAppendF(&out_data_string, "\n\n%s:\n", kHeaderSysInfo);
  SYSTEM_INFO sys_info;
  ::GetNativeSystemInfo(&sys_info);
  FromSystemInfo(sys_info, &out_data_string);

  base::StringAppendF(&out_data_string, "\n\n%s:\n", kHeaderSysInfo2);
  ::GetSystemInfo(&sys_info);
  FromSystemInfo(sys_info, &out_data_string);

  if (include_env_variables) {
    out_data_string.append(2, '\n');
    AppendEnvironmentStrings(&out_data_string);
  }

  data_as_stream_.str(out_data_string);
}

void SystemInfoExtractor::FromSystemInfo(const SYSTEM_INFO& data,
                                         std::string* out_string) {
  out_string->append("Processor:\t");
  switch (data.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
      out_string->append("x64");
      break;
    case PROCESSOR_ARCHITECTURE_IA64:
      out_string->append("itanium");
      break;
    case PROCESSOR_ARCHITECTURE_INTEL:
      out_string->append("x86");
      break;
    default:
      out_string->append("unknown");
      break;
  }
  out_string->append(1, '\n');

  base::StringAppendF(out_string, "%s:\t%d\n",
                      kHeaderPageSize, data.dwPageSize);
  base::StringAppendF(out_string, "%s:\t%d\n",
                      kHeaderProcs, data.dwNumberOfProcessors);
  base::StringAppendF(out_string, "%s:\t0x%04hX\n",
                      kHeaderProcRev, data.wProcessorRevision);
  base::StringAppendF(out_string, "%s:\t0x%08X\n",
                      kHeaderProcMask, data.dwActiveProcessorMask);
}

void SystemInfoExtractor::ListEnvironmentStrings(const wchar_t* string_table,
                                                 std::string* out_string) {
  // string_table is a table of 0-separated strings terminated by an empty
  // string (two zeros in a row, that is). The loop below will transform it
  // into a sequence of \n separated char strings.
  // Having the block start with a single 0 would contradict specs so I just
  // ignore that.
  while (*string_table) {
    const wchar_t* next_zero = string_table;
    for (; *next_zero; ++next_zero) {
      // Just looking, noop.
    }
    std::string next_block;
    WideToUTF8(string_table, next_zero - string_table, &next_block);
    out_string->append(next_block);
    out_string->append(1, '\n');
    string_table = next_zero + 1;
  }
}

void SystemInfoExtractor::AppendEnvironmentStrings(std::string* out_string) {
  wchar_t* env_strings = ::GetEnvironmentStrings();
  if (env_strings) {
    ListEnvironmentStrings(env_strings, out_string);
    ::FreeEnvironmentStrings(env_strings);
  }
}
