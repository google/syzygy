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

#include <algorithm>

#include "base/file_path.h"
#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/scoped_ptr.h"
#include "sawdust/tracer/tracer_unittest_util.h"

wchar_t* CreateNullNullTerminatedDescription(const std::string& in_table,
                                             size_t* buffer_size) {
  size_t table_length = in_table.size() + 1;
  scoped_array<wchar_t> string_table(new wchar_t[table_length]);

  // in_table is test data and I can require whatever I want.
  // (1) must have data,
  // (2) the last string has to finish with \n, too.
  // (3) no empty strings.
  if (in_table.empty() || in_table[in_table.size() - 1] != '\n' ||
      std::string::npos != in_table.find("\n\n")) {
    NOTREACHED() << "Test data doesn't meet requirements.";
    return NULL;
  }

  std::copy(in_table.begin(), in_table.end(), string_table.get());

  // string_table should now contain the equivalent of in_table (letters
  // cast to wchar_t in assignment). Now replace all \n with \0.
  std::replace<wchar_t*, wchar_t>(string_table.get(),
                                  string_table.get() + table_length,
                                  '\n', 0);
  string_table.get()[table_length - 1] = 0;
  DCHECK_EQ(string_table.get()[table_length - 2], 0);  // Need two trailing 0s.
  if (buffer_size)
    *buffer_size = table_length;

  return string_table.release();
}

void SplitStringFromDblNullTerminated(const wchar_t* dbl_null_term,
    std::vector<std::wstring>* parsed_out_strings) {
  // string_table is a table of 0-separated strings terminated by an empty
  // string (two zeros in a row, that is). The loop below will transform it
  // into a sequence of \n separated char strings.
  // Having the block start with a single 0 would contradict specs so I just
  // ignore that.
  if (parsed_out_strings == NULL || dbl_null_term == NULL) {
    NOTREACHED() << "Invalid input data";
    return;
  }

  const wchar_t* string_table = dbl_null_term;
  while (*string_table) {
    parsed_out_strings->push_back(std::wstring(string_table));
    const wchar_t* next_zero = string_table + parsed_out_strings->back().size();
    DCHECK_EQ(*next_zero, 0);
    string_table = next_zero + 1;
  }
}

Value* LoadJsonDataFile(const std::wstring& resource_title) {
  FilePath exe_location;
  PathService::Get(base::FILE_EXE, &exe_location);
  FilePath test_data_path = exe_location.DirName().Append(resource_title);
  Value* return_value = NULL;
  std::string json_content;
  if (file_util::PathExists(test_data_path) &&
      file_util::ReadFileToString(test_data_path, &json_content)) {
    return_value = base::JSONReader::Read(json_content, true);
  }

  return return_value;
}
