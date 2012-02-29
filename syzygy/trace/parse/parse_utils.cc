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

#include "syzygy/trace/parse/parse_utils.h"

#include "sawbuck/common/buffer_parser.h"

namespace trace {
namespace parser {

bool ParseTraceFileHeaderBlob(const TraceFileHeader& header,
                              TraceFileHeaderBlob* blob) {
  DCHECK(blob != NULL);

  if (header.header_size < offsetof(TraceFileHeader, blob_data)) {
    LOG(ERROR) << "Invalid header size.";
    return false;
  }

  size_t blob_length = header.header_size -
      offsetof(TraceFileHeader, blob_data);

  BinaryBufferReader reader(header.blob_data, blob_length);

  if (!reader.ReadString(&blob->module_path, &blob->module_path_length)) {
    LOG(ERROR) << "Malformed TraceFileHeader module path.";
    return false;
  }

  if (!reader.ReadString(&blob->command_line, &blob->command_line_length)) {
    LOG(ERROR) << "Malformed TraceFileHeader command line.";
    return false;
  }

  // Parse the environment string.
  reader.Peek(&blob->environment);
  size_t env_string_count = 0;
  size_t total_env_length = 0;
  while (true) {
    const wchar_t* string = NULL;
    size_t length = 0;
    if (!reader.ReadString(&string, &length)) {
      LOG(ERROR) << "Malformed TraceFileHeader environment string.";
      return false;
    }

    total_env_length += length + 1;
    if (length == 0 && env_string_count > 0)
      break;
    ++env_string_count;
  }

  if (reader.RemainingBytes() > 0) {
    LOG(ERROR) << "TraceFileHeader blob contains extra data.";
    return false;
  }

  blob->environment_length = total_env_length;

  return true;
}

}  // namespace parser
}  // namespace trace
