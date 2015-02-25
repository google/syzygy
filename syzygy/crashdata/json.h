// Copyright 2015 Google Inc. All Rights Reserved.
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
// Simple conversion of crash metadata to/from JSON. Useful for quickly
// dumping contents of crashdata buffers, and for unittests.

#ifndef SYZYGY_CRASHDATA_JSON_H_
#define SYZYGY_CRASHDATA_JSON_H_

#include "syzygy/crashdata/crashdata.h"

namespace crashdata {

// Converts the provided crashdata protobuf to an equivalent JSON
// representation.
// @param pretty_print If true the resulting JSON will be pretty-printed.
// @param value A value object containing crash metadata.
// @param output The destination buffer.
// @returns true on success, false otherwise.
bool ToJson(bool pretty_print, const Value* value, std::string* output);

}  // namespace crashdata

#endif  // SYZYGY_CRASHDATA_JSON_H_
