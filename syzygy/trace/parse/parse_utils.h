// Copyright 2012 Google Inc. All Rights Reserved.
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
// Declares utility functions used by the parsers and various unittests.

#ifndef SYZYGY_TRACE_PARSE_PARSE_UTILS_H_
#define SYZYGY_TRACE_PARSE_PARSE_UTILS_H_

#include "syzygy/trace/protocol/call_trace_defs.h"

namespace trace {
namespace parser {

// Parses a windows environment string.
// @param env_string a doubly-zero terminated compound environment string.
// @param env_strings the object to receive the parsed environment strings.
bool ParseEnvironmentStrings(const wchar_t* env_string,
                             TraceEnvironmentStrings* env_strings);

// Parses the blob of variable sized data fields at the end of @p header.
// @param header the header to parse.
// @param module_path the string to receive the module path.
// @param command_line the string to receive the command line.
// @param env_strings the object to receive the environment strings.
// @returns true on success, false otherwise.
bool ParseTraceFileHeaderBlob(const TraceFileHeader& header,
                              std::wstring* module_path,
                              std::wstring* command_line,
                              TraceEnvironmentStrings* env_strings);

}  // namespace parser
}  // namespace trace

#endif  // SYZYGY_TRACE_PARSE_PARSE_UTILS_H_
