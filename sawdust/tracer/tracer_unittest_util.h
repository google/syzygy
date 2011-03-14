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
// The tool for uploading tracer's result to the crash server.
#ifndef SAWDUST_TRACER_TRACER_UNITTEST_UTIL_H_
#define SAWDUST_TRACER_TRACER_UNITTEST_UTIL_H_

#include <string>
#include <vector>

// Create a double-null terminated wide-char string from a multi-line
// (\n separated) text.
wchar_t* CreateNullNullTerminatedDescription(const std::string& in_table,
                                             size_t* buffer_size);

// Split a double-null terminated wide char string into separate wstrings held
// in the vector.
void SplitStringFromDblNullTerminated(const wchar_t* dbl_null_term,
    std::vector<std::wstring>* parsed_out_strings);

#endif  // SAWDUST_TRACER_TRACER_UNITTEST_UTIL_H_

