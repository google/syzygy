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

#include "syzygy/experimental/protect/protect_lib/protect_app.h"

#include <ctime>
#include <iostream>
#include <sstream>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/instrument/instrument_app.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_transform_policy.h"
#include "syzygy/experimental/protect/protect_lib/integrity_check_transform.h"
#include "syzygy/experimental/protect/protect_lib/protect_flummox.h"

namespace protect {
bool ProtectApp::ParseCommandLine(const base::CommandLine* cmd_line) {
  instrumenter_.reset(new CustomFlummoxInstrumenter());
  return instrumenter_->ParseCommandLine(cmd_line);
}

bool ProtectApp::SetUp() {
  std::srand(std::time(0));
  return true;
}

int ProtectApp::Run() {
  return instrumenter_->Instrument();
}
} // namespace protect
