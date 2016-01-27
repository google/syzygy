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

#include "syzygy/poirot/minidump_processor.h"

#include <string>

#include "base/logging.h"
#include "syzygy/crashdata/json.h"
#include "syzygy/kasko/api/client.h"
#include "syzygy/minidump/minidump.h"

namespace poirot {

MinidumpProcessor::MinidumpProcessor(const base::FilePath& input_minidump)
    : input_minidump_(input_minidump), processed_(false) {
}

bool MinidumpProcessor::ProcessDump() {
  DCHECK(!input_minidump_.empty());
  DCHECK(!processed_);
  minidump::FileMinidump minidump;

  if (!minidump.Open(input_minidump_)) {
    LOG(ERROR) << "Unable to open the minidump.";
    return false;
  }

  // Get the Kasko stream from the minidump.
  minidump::Minidump::Stream stream =
      minidump.FindNextStream(nullptr, kasko::api::kProtobufStreamType);
  if (!stream.IsValid()) {
    LOG(ERROR) << "Unable to read the Kasko stream.";
    return false;
  }

  // Read the stream content and initialize the protobuf with it.
  std::string stream_content;
  if (!stream.ReadAndAdvanceBytes(stream.remaining_length(), &stream_content)) {
    LOG(ERROR) << "Unable to read the minidump bytes.";
    return false;
  }
  if (!protobuf_value_.ParseFromString(stream_content)) {
    LOG(ERROR) << "Unable to parse the protobuf from the Kasko stream.";
    return false;
  }
  processed_ = true;
  return true;
}

bool MinidumpProcessor::GenerateJsonOutput(FILE* file) {
  DCHECK_NE(static_cast<FILE*>(nullptr), file);
  DCHECK(processed_);

  std::string out_str;
  if (!crashdata::ToJson(true, &protobuf_value_, &out_str)) {
    LOG(ERROR) << "Unable to convert the protobuf to JSON.";
    return false;
  }
  ::fprintf(file, "%s", out_str.c_str());
  return true;
}

} // namespace poirot
