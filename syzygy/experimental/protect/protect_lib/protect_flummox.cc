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

#include "syzygy/experimental/protect/protect_lib/protect_flummox.h"

#include <algorithm>
#include <sstream>

#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "syzygy/application/application.h"

namespace protect {

bool CustomFlummoxInstrumenter::InstrumentPrepare() {
  return config_.ReadFromJSONPath(flummox_config_path_);
}

bool CustomFlummoxInstrumenter::InstrumentImpl() {
  flummox_transform_.reset(
    new protect::IntegrityCheckTransform(&config_));

  if (!relinker_->AppendTransform(flummox_transform_.get())) {
    LOG(ERROR) << "Failed to apply transform.";
    return false;
  }

  layout_transform_.reset(
    new protect::IntegrityCheckLayoutTransform(&config_));

  if (!relinker_->AppendLayoutTransform(layout_transform_.get())) {
    LOG(ERROR) << "Failed to apply layout transform.";
    return false;
  }
  return true;
}

bool CustomFlummoxInstrumenter::DoCommandLineParse(
  const base::CommandLine* command_line) {
  DCHECK(command_line != nullptr);

  if (!Super::DoCommandLineParse(command_line))
    return false;

  // Parse the target list filename.
  flummox_config_path_ = application::AppImplBase::AbsolutePath(
    command_line->GetSwitchValuePath("flummox-config-path"));
  if (flummox_config_path_.empty()) {
    LOG(ERROR) << "You must specify --flummox-config-path.";
    return false;
  }

  return true;
}

}  // namespace protect
