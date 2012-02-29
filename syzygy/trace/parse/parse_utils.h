// Copyright 2012 Google Inc.
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

// Used to extract variable-length fields from the binary blob at the tail
// of the header.
struct TraceFileHeaderBlob {
  const wchar_t* module_path;  // This is a NULL terminated string.
  size_t module_path_length;  // Length does not include NULL terminator.

  const wchar_t* command_line;  // This is a NULL terminated string.
  size_t command_line_length;  // Length does not include NULL terminator.

  const wchar_t* environment;  // This is an array.
  size_t environment_length;  // Length includes all NULL characters.
};

// Parses the blob of variable sized data fields at the end of @p header.
// @param header the header to parse.
// @param blob the object to receive the parsed values.
// @returns true on success, false otherwise.
bool ParseTraceFileHeaderBlob(const TraceFileHeader& header,
                              TraceFileHeaderBlob* blob);

}  // namespace parser
}  // namespace trace

#endif  // SYZYGY_TRACE_PARSE_PARSE_UTILS_H_
