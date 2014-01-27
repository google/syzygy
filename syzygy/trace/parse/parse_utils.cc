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

#include "syzygy/trace/parse/parse_utils.h"

#include "base/logging.h"
#include "syzygy/common/buffer_parser.h"

namespace trace {
namespace parser {

namespace {

using ::common::BinaryBufferReader;

bool ParseString(BinaryBufferReader* reader, std::wstring* output) {
  DCHECK(reader != NULL);

  const wchar_t* string = NULL;
  size_t length = 0;
  if (!reader->ReadString(&string, &length)) {
    LOG(ERROR) << "Failed to parse string from TraceFileHeader blob.";
    return false;
  }

  if (output != NULL)
    *output = string;

  return true;
}

bool ParseEnvironmentStrings(BinaryBufferReader* reader,
                             TraceEnvironmentStrings* env_strings) {
  DCHECK(reader != NULL);

  if (env_strings != NULL)
    env_strings->clear();

  // Parse the environment string.
  size_t env_string_count = 0;
  while (true) {
    const wchar_t* string = NULL;
    size_t length = 0;
    if (!reader->ReadString(&string, &length)) {
      LOG(ERROR) << "Failed to parse environment strings from TraceFileHeader.";
      return false;
    }

    if (length == 0 && env_string_count > 0)
      return true;

    // Parse this environment string by splitting it at the first '=' sign.
    if (env_strings != NULL) {
      // If we don't find a '=' we assume the whole thing is a key. This is
      // actually strictly invalid, but no harm done.
      const wchar_t* split = ::wcschr(string, L'=');
      if (split != NULL) {
        env_strings->push_back(std::make_pair(
            std::wstring(string, split - string),
            std::wstring(split + 1)));
      } else {
        env_strings->push_back(std::make_pair(std::wstring(string),
                                              std::wstring()));
      }
    }

    ++env_string_count;
  }
}

}  // namespace

bool ParseEnvironmentStrings(const wchar_t* env_string,
                             TraceEnvironmentStrings* env_strings) {
  DCHECK(env_string != NULL);
  DCHECK(env_strings != NULL);

  // Search for the double zero termination.
  size_t i = 2;
  while (true) {
    if (env_string[i - 2] == 0 && env_string[i - 1] == 0)
      break;

    ++i;
  }

  BinaryBufferReader reader(env_string, sizeof(env_string[0]) * i);
  return ParseEnvironmentStrings(&reader, env_strings);
}

bool ParseTraceFileHeaderBlob(const TraceFileHeader& header,
                              std::wstring* module_path,
                              std::wstring* command_line,
                              TraceEnvironmentStrings* env_strings) {
  if (header.header_size < offsetof(TraceFileHeader, blob_data)) {
    LOG(ERROR) << "Invalid header size.";
    return false;
  }

  size_t blob_length = header.header_size -
      offsetof(TraceFileHeader, blob_data);

  BinaryBufferReader reader(header.blob_data, blob_length);

  if (!ParseString(&reader, module_path))
    return false;
  if (!ParseString(&reader, command_line))
    return false;
  if (!ParseEnvironmentStrings(&reader, env_strings))
    return false;

  if (reader.RemainingBytes() > 0) {
    LOG(ERROR) << "TraceFileHeader blob contains extra data.";
    return false;
  }

  return true;
}

}  // namespace parser
}  // namespace trace
