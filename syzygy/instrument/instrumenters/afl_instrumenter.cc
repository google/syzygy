// Copyright 2017 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/instrumenters/afl_instrumenter.h"

#include "base/logging.h"
#include "base/values.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "syzygy/application/application.h"
#include "syzygy/common/indexed_frequency_data.h"

namespace instrument {
namespace instrumenters {

bool AFLInstrumenter::ReadFromJSON(const std::string& json) {
  std::unique_ptr<base::Value> value(base::JSONReader::Read(json).release());

  if (!value || !value->IsType(base::Value::TYPE_DICTIONARY)) {
    LOG(ERROR) << "Invalid or empty JSON configuration.";
    return false;
  }

  const base::DictionaryValue* outer_dict =
      reinterpret_cast<const base::DictionaryValue*>(value.get());

  const base::ListValue* whitelist = nullptr;
  const base::ListValue* blacklist = nullptr;
  const base::ListValue* to_parse_list = nullptr;

  outer_dict->GetList("whitelist", &whitelist);
  outer_dict->GetList("blacklist", &blacklist);

  if (whitelist == nullptr && blacklist == nullptr) {
    LOG(ERROR) << "JSON file must contain either 'whitelist' or 'blacklist'.";
    return false;
  }

  if (whitelist != nullptr && blacklist != nullptr) {
    LOG(ERROR) << "'whitelist' and 'blacklist' are mutally exclusive.";
    return false;
  }

  whitelist_mode_ = whitelist != nullptr;
  if (whitelist_mode_) {
    to_parse_list = whitelist;
  } else {
    to_parse_list = blacklist;
  }

  base::ListValue::const_iterator list_iter = to_parse_list->begin();
  for (; list_iter != to_parse_list->end(); ++list_iter) {
    std::string fname;
    if (!(*list_iter)->GetAsString(&fname)) {
      LOG(ERROR) << "The list must be composed of strings only.";
      return false;
    }

    target_set_.insert(fname);
  }

  if (target_set_.size() == 0) {
    LOG(ERROR) << "List cannot be empty.";
    return false;
  }

  return true;
}

bool AFLInstrumenter::ReadFromJSONPath(const base::FilePath& path) {
  std::string file_string;
  if (!base::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read file to string.";
    return false;
  }

  if (!ReadFromJSON(file_string)) {
    LOG(ERROR) << "Unable to parse JSON string.";
    return false;
  }

  return true;
}

bool AFLInstrumenter::DoCommandLineParse(
    const base::CommandLine* command_line) {
  if (!Super::DoCommandLineParse(command_line))
    return false;

  // Parse the config path parameter (optional).
  if (command_line->HasSwitch("config")) {
    base::FilePath config_path = application::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("config"));

    if (!ReadFromJSONPath(config_path)) {
      LOG(ERROR) << "Unable to parse JSON file.";
      return false;
    }
  }

  // Parse the force decomposition flag (optional).
  force_decomposition_ = command_line->HasSwitch("force-decompose");
  if (force_decomposition_) {
    LOG(INFO) << "Force decomposition mode enabled.";
  }

  // Parse the multithread flag (optional).
  multithread_mode_ = command_line->HasSwitch("multithread");
  if (multithread_mode_) {
    LOG(INFO) << "Thread-safe instrumentation mode enabled.";
  }

  // Parse the cookie check hook flag (optional).
  cookie_check_hook_ = command_line->HasSwitch("cookie-check-hook");
  if (cookie_check_hook_) {
    LOG(INFO) << "Cookie check hook mode enabled.";
  }

  return true;
}

bool AFLInstrumenter::InstrumentPrepare() {
  return true;
}

bool AFLInstrumenter::InstrumentImpl() {
  transformer_.reset(new instrument::transforms::AFLTransform(
      target_set_, whitelist_mode_, force_decomposition_, multithread_mode_,
      cookie_check_hook_));

  if (!relinker_->AppendTransform(transformer_.get())) {
    LOG(ERROR) << "AppendTransform failed.";
    return false;
  }

  add_bb_addr_stream_mutator_.reset(
      new instrument::mutators::AddIndexedDataRangesStreamPdbMutator(
          transformer_->bb_ranges(), common::kBasicBlockRangesStreamName));

  if (!relinker_->AppendPdbMutator(add_bb_addr_stream_mutator_.get())) {
    LOG(ERROR) << "AppendPdbMutator failed.";
    return false;
  }

  return true;
}

const char* AFLInstrumenter::InstrumentationMode() {
  return "afl";
}
}  // namespace instrumenters
}  // namespace instrument
