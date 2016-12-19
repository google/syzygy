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
#include "syzygy/experimental/protect/protect_lib/protect_utils.h"

#include "base/values.h"
#include "base/json/json_reader.h"

namespace protect {

bool ShouldProcessBlock(const BlockGraph::Block* block,
                        const std::map<std::string, bool> target_names) {
  return (target_names.find(block->name()) != target_names.end());
}
bool ShouldPostProcessBlock(
    const BlockGraph::Block* block,
    const std::map<uint64_t, BlockGraph::Label> *id_to_label) {
  if (block->labels().size() == 0) return false;
  if (GetBasicBlockIdByLabel(block->labels().begin()->second,
                             id_to_label) == -1) {
    return false;
    }
  return true;
}
uint64_t GetBasicBlockIdByLabel(
    const BlockGraph::Label label,
    const std::map<uint64_t, BlockGraph::Label> *id_to_label){
  auto it = id_to_label->begin();
  for (; it != id_to_label->end(); ++it) {
    if (it->second == label)
      return it->first;
  }

  return (uint64_t)-1;
}

void GetChunkTokensFromlabel(const std::string label,
                             uint64_t *chunk_bb_id,
                             uint32_t *chunk_index){
  //split the string
  std::istringstream iss(label);
  std::vector<std::string> tokens;
  copy(std::istream_iterator<std::string>(iss),
       std::istream_iterator<std::string>(),
       back_inserter(tokens)
       );
  DCHECK(tokens.size() > 2);
  *chunk_bb_id = std::stoull(tokens.at(1));
  *chunk_index = std::stoul(tokens.at(2));
}

uint64_t GetChunkUniqueKey(const uint64_t bb_id, const uint32_t chunk_index){
  return std::hash<std::string>()(std::to_string(bb_id)
                                  + std::to_string(chunk_index));
}

using base::DictionaryValue;
using base::ListValue;
using base::Value;

bool FlummoxConfig::ReadFromJSON(const std::string& json) {
  bool input_add_copy = false;
  double input_chunk_coverage = 1.0;

  std::unique_ptr<Value> value(base::JSONReader::Read(json).release());
  if (value.get() == nullptr) {
    LOG(ERROR) << "Invalid or empty configuration JSON.";
    return false;
  }
  if (value->GetType() != Value::TYPE_DICTIONARY) {
    LOG(ERROR) << "Invalid allocation filter transform file.";
    return false;
  }

  const DictionaryValue* outer_dict =
    reinterpret_cast<const DictionaryValue*>(value.get());


  std::string chunk_coverage_key("chunk_coverage");
  if (outer_dict->HasKey(chunk_coverage_key) &&
      !outer_dict->GetDouble(chunk_coverage_key, &input_chunk_coverage)) {
    LOG(ERROR) << chunk_coverage_key << " must be a double.";
    return false;
  }
  if (input_chunk_coverage > 10.0 || input_chunk_coverage < 0.0) {
    LOG(ERROR) << chunk_coverage_key << " must be between [0.0,10.0] .";
    return false;
  }


  std::string targets_key("targets");
  const DictionaryValue* targets_dict = nullptr;

  if (!outer_dict->GetDictionary(targets_key, &targets_dict)) {
    LOG(ERROR) << "Outer dictionary must contain key 'targets'.";
    return false;
  }

  std::set<std::string> temp_target_set;
  DictionaryValue::Iterator it(*targets_dict);
  for (; !it.IsAtEnd(); it.Advance()) {
    std::string function_name = it.key();
    const ListValue* strategy_list = nullptr;
    if (!it.value().GetAsList(&strategy_list))  {
      LOG(ERROR) << "Strategy list expected.";
      return false;
    }
    // TODO(huangs): Load strategies.
    // for (const Value* strategy : *strategy_list) { }
    temp_target_set.insert(function_name);
  }

  std::string add_copy_key("add_copy");
  if (outer_dict->HasKey(add_copy_key) &&
      !outer_dict->GetBoolean(add_copy_key, &input_add_copy)) {
    LOG(ERROR) << add_copy_key << " must be a boolean.";
    return false;
  }


  // Success!
  target_set_.swap(temp_target_set);
  add_copy_ = input_add_copy;
  chunk_checking_coverage_ = input_chunk_coverage;
  return true;
}

bool FlummoxConfig::ReadFromJSONPath(
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

} // namespace protect