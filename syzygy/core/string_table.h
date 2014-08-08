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
// A StringTable is responsible of string allocation and string sharing.
// Pointers to interned strings are valid until the destruction of the
// StringTable.
//
// Example use is as follows:
//
// StringStable strtab;
// const std::string& str1 = strtab.InternString("dummy");
// const std::string& str2 = strtab.InternString("dummy");
//
// str1 and str2 are the same instance of a string holding the value "dummy".

#ifndef SYZYGY_CORE_STRING_TABLE_H_
#define SYZYGY_CORE_STRING_TABLE_H_

#include <set>
#include <string>

#include "base/basictypes.h"
#include "base/strings/string_piece.h"

namespace core {

class StringTable {
 public:
  // Default constructor.
  StringTable() {
  }

  // A pool of strings is maintained privately. If the pool already contains a
  // string equal to @p str, then the string from the pool is returned.
  // Otherwise, the string is added to the pool and a reference is returned.
  // @param str The string to internalized.
  // @returns a canonical representation for this string.
  const std::string& InternString(const base::StringPiece& str);

 protected:
  std::set<std::string> string_table_;

 private:
  DISALLOW_COPY_AND_ASSIGN(StringTable);
};

}  // namespace core

#endif  // SYZYGY_CORE_STRING_TABLE_H_
