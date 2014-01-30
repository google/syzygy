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

#include "syzygy/grinder/indexed_frequency_data_serializer.h"

#include <string>
#include <utility>

#include "base/stringprintf.h"
#include "base/files/file_path.h"
#include "base/json/json_reader.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace grinder {

namespace {

using basic_block_util::EntryCountType;
using basic_block_util::IndexedFrequencyInformation;
using basic_block_util::IndexedFrequencyMap;
using basic_block_util::ModuleIndexedFrequencyMap;
using basic_block_util::ModuleInformation;
using core::JSONFileWriter;
using core::RelativeAddress;

const char kMetadata[] = "metadata";
const char kFrequencies[] = "frequencies";
const char kDescription[] = "description";
const char kNumEntriesKey[] = "num_entries";
const char kNumColumnsKey[] = "num_columns";
const char kDataTypeKey[] = "data_type";
const char kFrequencySizeKey[] = "frequency_size";

bool OutputFrequencyData(
    JSONFileWriter* writer,
    const ModuleInformation& module_information,
    const IndexedFrequencyInformation& frequency_info) {
  DCHECK(writer != NULL);

  // Start a new dictionary.
  if (!writer->OpenDict())
    return false;

  // Pour the module information into a PE Metadata object, for convenient
  // JSON serialization.
  pe::Metadata metadata;
  if (!metadata.Init(pe::PEFile::Signature(module_information)))
    return false;

  // Output the module metadata.
  if (!writer->OutputKey(kMetadata) || !metadata.SaveToJSON(writer))
    return false;

  // Output the module information.
  std::string data_type_str;
  if (!common::IndexedFrequencyDataTypeToString(frequency_info.data_type,
                                                &data_type_str)) {
    return false;
  }
  if (!writer->OutputComment("Indexed frequency data module description.") ||
      !writer->OutputKey(kDescription) ||
      !writer->OpenDict() ||
      !writer->OutputKey(kNumEntriesKey) ||
      !writer->OutputInteger(frequency_info.num_entries) ||
      !writer->OutputKey(kNumColumnsKey) ||
      !writer->OutputInteger(frequency_info.num_columns) ||
      !writer->OutputKey(kDataTypeKey) ||
      !writer->OutputString(data_type_str) ||
      !writer->OutputKey(kFrequencySizeKey) ||
      !writer->OutputInteger(frequency_info.frequency_size) ||
      !writer->CloseDict()) {
    return false;
  }

  // Output the frequency array.
  const IndexedFrequencyMap& frequencies = frequency_info.frequency_map;
  if (!writer->OutputComment(base::StringPrintf(
          "%d basic-block frequencies.", frequencies.size()).c_str()) ||
      !writer->OutputKey(kFrequencies) ||
      !writer->OpenList()) {
    return false;
  }

  // Build a set of keys to output.
  size_t num_columns = 0;
  std::set<RelativeAddress> keys;
  IndexedFrequencyMap::const_iterator it = frequencies.begin();
  for (; it != frequencies.end(); ++it) {
    RelativeAddress addr = it->first.first;
    size_t column = it->first.second;
    if (it->second != 0) {
      keys.insert(addr);
      num_columns = std::max(num_columns, column + 1);
    }
  }

  // For each key with at least one non-zero column, output a block with each
  // column.
  std::set<RelativeAddress>::iterator key = keys.begin();
  for (; key != keys.end(); ++key) {
    if (!writer->OpenList() || !writer->OutputInteger(key->value()))
      return false;
    for (size_t column = 0; column < num_columns; ++column) {
      IndexedFrequencyMap::const_iterator data =
          frequencies.find(std::make_pair(*key, column));
      int32 value = 0;
      if (data != frequencies.end())
        value = data->second;
      if (!writer->OutputInteger(value))
        return false;
    }
    if (!writer->CloseList())
      return false;
  }

  // Close the entry count array.
  if (!writer->CloseList())
    return false;

  // Close the dictionary.
  if (!writer->CloseDict())
    return false;

  // And we're done.
  return true;
}

bool ReadFrequencyData(const base::DictionaryValue* dict_value,
                       ModuleIndexedFrequencyMap* module_frequency_map) {
  DCHECK(dict_value != NULL);
  DCHECK(module_frequency_map != NULL);

  // Load the metadata about the image.
  const base::DictionaryValue* metadata_dict = NULL;
  if (!dict_value->GetDictionary(kMetadata, &metadata_dict)) {
    LOG(ERROR) << "Missing or invalid " << kMetadata << " entry.";
    return false;
  }

  pe::Metadata metadata;
  if (!metadata.LoadFromJSON(*metadata_dict)) {
    // The loader will log any errors.
    return false;
  }

  // Extract the information list.
  const base::DictionaryValue* information_dict = NULL;
  if (!dict_value->GetDictionary(kDescription, &information_dict)) {
    LOG(ERROR) << "Missing or invalid " << kDescription << " entry.";
    return false;
  }

  // Extract the frequencies list.
  const base::ListValue* frequency_list = NULL;
  if (!dict_value->GetList(kFrequencies, &frequency_list)) {
    LOG(ERROR) << "Missing or invalid " << kFrequencies << " entry.";
    return false;
  }

  // Insert a new IndexedFrequencyMap record for this module.
  const ModuleInformation& module_information = metadata.module_signature();
  std::pair<ModuleIndexedFrequencyMap::iterator, bool> result =
      module_frequency_map->insert(std::make_pair(
          module_information, IndexedFrequencyInformation()));

  // Validate that we really did insert a new module into the map.
  if (!result.second) {
    LOG(ERROR) << "Found duplicate entries for " << module_information.path
               << ".";
    return false;
  }

  // Populate frequency information.
  IndexedFrequencyInformation& frequency_info = result.first->second;
  int32 info_num_entries = 0;
  int32 info_num_columns = 0;
  std::string info_data_type_str;
  int32 info_frequency_size = 0;
  if (!information_dict->GetInteger(kNumEntriesKey, &info_num_entries) ||
      !information_dict->GetInteger(kNumColumnsKey, &info_num_columns) ||
      !information_dict->GetString(kDataTypeKey, &info_data_type_str) ||
      !information_dict->GetInteger(kFrequencySizeKey, &info_frequency_size)) {
    return false;
  }
  frequency_info.num_entries = info_num_entries;
  frequency_info.num_columns = info_num_columns;
  if (!common::ParseFrequencyDataType(info_data_type_str,
                                      &frequency_info.data_type)) {
    return false;
  }
  frequency_info.frequency_size = info_frequency_size;

  // Populate the IndexedFrequencyMap with the values in the list.
  IndexedFrequencyMap& values = result.first->second.frequency_map;
  size_t num_entries = frequency_list->GetSize();
  for (size_t i = 0; i < num_entries; ++i) {
    const base::ListValue* entry = NULL;
    if (!frequency_list->GetList(i, &entry))
      return false;
    size_t num_columns = entry->GetSize();
    if (num_columns == 0)
      return false;

    // Get the basic block RVA.
    int32 address = 0;
    if (!entry->GetInteger(0, &address))
      return false;
    if (address < 0) {
      LOG(ERROR) << "Invalid relative address in frequency list.";
      return false;
    }

    // Retrieve each column.
    for (size_t column = 1; column < num_columns; ++column) {
      basic_block_util::EntryCountType entry_count = 0;
      if (!entry->GetInteger(column, &entry_count))
        return false;
      if (entry_count < 0) {
        LOG(ERROR) << "Invalid value in frequency list.";
        return false;
      }

      // Add this entry to our map.
      if (!values.insert(std::make_pair(std::make_pair(
          core::RelativeAddress(address), column - 1), entry_count)).second) {
        LOG(ERROR) << "Duplicate basic block address in frequency list.";
        return false;
      }
    }
  }

  // And we're done.
  return true;
}

}  // namespace

IndexedFrequencyDataSerializer::IndexedFrequencyDataSerializer()
    : pretty_print_(false) {
}

bool IndexedFrequencyDataSerializer::SaveAsJson(
    const ModuleIndexedFrequencyMap& frequency_map, FILE* file) {
  DCHECK(file != NULL);
  core::JSONFileWriter writer(file, pretty_print_);

  // Open the list;
  if (!writer.OpenList())
    return false;

  // Output each entry;
  ModuleIndexedFrequencyMap::const_iterator it = frequency_map.begin();
  for (; it != frequency_map.end(); ++it) {
    if (!OutputFrequencyData(&writer, it->first, it->second))
      return false;
  }

  // Close the list.
  if (!writer.CloseList())
    return false;

  return true;
}

bool IndexedFrequencyDataSerializer::SaveAsJson(
    const ModuleIndexedFrequencyMap& frequency_map,
    const base::FilePath& path) {
  DCHECK(!path.empty());
  file_util::ScopedFILE file(file_util::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Failed to open " << path.value() << " for reading.";
    return false;
  }

  if (!SaveAsJson(frequency_map, file.get())) {
    LOG(ERROR) << "Failed to write JSON data to " << path.value() << ".";
    return false;
  }

  return true;
}

bool IndexedFrequencyDataSerializer::LoadFromJson(
    const base::FilePath& path,
    ModuleIndexedFrequencyMap* module_frequency_map) {
  DCHECK(module_frequency_map != NULL);
  DCHECK(!path.empty());

  std::string json_string;
  if (!file_util::ReadFileToString(path, &json_string)) {
    LOG(ERROR) << "Failed to read '" << path.value() << "'.";
    return false;
  }

  base::JSONReader json_reader;
  std::string error_msg;
  scoped_ptr<base::Value> json_value(
      json_reader.ReadAndReturnError(
          json_string, base::JSON_ALLOW_TRAILING_COMMAS, NULL, &error_msg));
  if (json_value.get() == NULL) {
    LOG(ERROR) << "Failed to parse '" << path.value() << "' as JSON ("
               << error_msg << ").";
    return false;
  }

  if (!PopulateFromJsonValue(json_value.get(), module_frequency_map))
    return false;

  return true;
}

bool IndexedFrequencyDataSerializer::PopulateFromJsonValue(
    const base::Value* json_value,
    ModuleIndexedFrequencyMap* module_frequency_map) {
  DCHECK(json_value != NULL);
  DCHECK(module_frequency_map != NULL);

  module_frequency_map->clear();

  // Extract the top level list of module.
  const base::ListValue* module_list = NULL;
  if (!json_value->GetAsList(&module_list)) {
    LOG(ERROR) << "Expected a list as the top level JSON construct.";
    return false;
  }

  // Extract each module.
  size_t num_modules = module_list->GetSize();
  for (size_t i = 0; i < num_modules; ++i) {
    const base::DictionaryValue* dict_value = NULL;
    if (!module_list->GetDictionary(i, &dict_value)) {
      LOG(ERROR) << "Invalid type for entry " << i << ".";
      return false;
    }
    if (!ReadFrequencyData(dict_value, module_frequency_map)) {
      // ReadFrequencyData() has already logged the error.
      return false;
    }
  }

  return true;
}

}  // namespace grinder
