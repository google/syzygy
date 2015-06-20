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

#include "syzygy/instrument/instrumenters/flummox_instrumenter.h"

#include <algorithm>
#include <sstream>

#include "base/values.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/strings/string_util.h"
#include "syzygy/application/application.h"

namespace instrument {
namespace instrumenters {

namespace {

using base::DictionaryValue;
using base::ListValue;
using base::Value;

}  // namespace

bool FlummoxInstrumenter::FlummoxConfig::ReadFromJSON(const std::string& json) {
  scoped_ptr<Value> value(base::JSONReader::Read(json));
  if (value.get() == NULL) {
    LOG(ERROR) << "Invalid or empty configuration JSON.";
    return false;
  }
  if (value->GetType() != Value::TYPE_DICTIONARY) {
    LOG(ERROR) << "Invalid allocation filter transform file.";
    return false;
  }

  const DictionaryValue* outer_dict =
    reinterpret_cast<const DictionaryValue*>(value.get());

  std::string targets_key("targets");
  const DictionaryValue* targets_dict = NULL;

  if (!outer_dict->GetDictionary(targets_key, &targets_dict)) {
    LOG(ERROR) << "Outer dictionary must contain key 'targets'.";
    return false;
  }

  std::set<std::string> temp_target_set;
  DictionaryValue::Iterator it(*targets_dict);
  for (; !it.IsAtEnd(); it.Advance()) {
    std::string function_name = it.key();
    const ListValue* strategy_list = NULL;
    if (!it.value().GetAsList(&strategy_list))  {
      LOG(ERROR) << "Strategy list expected.";
      return false;
    }
    // TODO(huangs): Load strategies.
    // for (const Value* strategy : *strategy_list) { }
    temp_target_set.insert(function_name);
  }

  target_set_.swap(temp_target_set);
  return true;
}

bool FlummoxInstrumenter::FlummoxConfig::ReadFromJSONPath(
    const base::FilePath& path) {
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

bool FlummoxInstrumenter::InstrumentImpl() {
  FlummoxConfig config;
  if (!config.ReadFromJSONPath(flummox_config_path_))
    return false;

  flummox_transform_.reset(
      new instrument::transforms::FillerTransform(config.target_set()));
  flummox_transform_->set_debug_friendly(debug_friendly_);

  if (!relinker_->AppendTransform(flummox_transform_.get())) {
    LOG(ERROR) << "Failed to apply transform.";
    return false;
  }

  return true;
}

bool FlummoxInstrumenter::DoCommandLineParse(
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

}  // namespace instrumenters
}  // namespace instrument
