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

#include "syzygy/grinder/basic_block_entry_count_serializer.h"

#include <string>
#include <utility>

#include "base/file_path.h"
#include "base/stringprintf.h"
#include "base/json/json_reader.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace grinder {

namespace  {

using core::JSONFileWriter;
using basic_block_util::EntryCountMap;
using basic_block_util::EntryCountType;
using basic_block_util::EntryCountVector;
using basic_block_util::ModuleInformation;

const char kMetadata[] = "metadata";
const char kEntryCounts[] = "entry_counts";

bool OutputEntryCount(
    JSONFileWriter* writer,
    const ModuleInformation& module_information,
    const EntryCountVector& entry_counts) {
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
  if (!writer->OutputKey(kMetadata) ||
      !metadata.SaveToJSON(writer)) {
    return false;
  }

  // Output the entry count array.
  if (!writer->OutputComment(base::StringPrintf(
          "%d basic-block counter values.", entry_counts.size()).c_str()) ||
      !writer->OutputKey(kEntryCounts) ||
      !writer->OpenList()) {
    return false;
  }

  for (size_t i = 0; i < entry_counts.size(); ++i) {
    if (!writer->OutputInteger(entry_counts[i]))
      return false;
  }

  if (!writer->CloseList())
    return false;

  // Close the dictionary.
  if (!writer->CloseDict())
    return false;

  // And we're done.
  return true;
}

bool ReadEntryCount(const base::DictionaryValue* dict_value,
                    EntryCountMap* entry_count_map) {
  DCHECK(dict_value != NULL);
  DCHECK(entry_count_map != NULL);

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

  // Extract the entry count list.
  const base::ListValue* entry_count_list = NULL;
  if (!dict_value->GetList(kEntryCounts, &entry_count_list)) {
    LOG(ERROR) << "Missing or invalid " << kEntryCounts << " entry.";
    return false;
  }

  // Convert the signature into a ModuleInformation struct.
  const pe::PEFile::Signature& signature = metadata.module_signature();
  ModuleInformation module_information;
  module_information.base_address = signature.base_address.value();
  module_information.image_checksum = signature.module_checksum;
  module_information.image_file_name = signature.path;
  module_information.module_size = signature.module_size;
  module_information.time_date_stamp = signature.module_time_date_stamp;

  // Insert a new entry count record for this module.
  std::pair<EntryCountMap::iterator, bool> result =
      entry_count_map->insert(std::make_pair(
          module_information, EntryCountVector()));

  // Validate that we really did insert a new module into the map.
  if (!result.second) {
    LOG(ERROR) << "Found duplicate entries for " << signature.path << ".";
    return false;
  }

  // Populate the entry count vector with the values in the list.
  EntryCountVector& values = result.first->second;
  size_t num_basic_blocks = entry_count_list->GetSize();
  values.reserve(num_basic_blocks);
  for (size_t i = 0; i < num_basic_blocks; ++i) {
    int number = 0;
    if (!entry_count_list->GetInteger(i, &number) || number < 0) {
      LOG(ERROR) << "Invalid value in entry count list.";
      return false;
    }
    values.push_back(number);
  }

  // And we're done.
  return true;
}

}  // namespace

BasicBlockEntryCountSerializer::BasicBlockEntryCountSerializer()
    : pretty_print_(false) {
}

bool BasicBlockEntryCountSerializer::SaveAsJson(
    const EntryCountMap& entry_count_map, FILE* file) {
  DCHECK(file != NULL);
  core::JSONFileWriter writer(file, pretty_print_);

  // Open the list;
  if (!writer.OpenList())
    return false;

  // Output each entry;
  EntryCountMap::const_iterator it = entry_count_map.begin();
  for (; it != entry_count_map.end(); ++it) {
    if (!OutputEntryCount(&writer, it->first, it->second))
      return false;
  }

  // Close the list.
  if (!writer.CloseList())
    return false;

  return true;
}

bool BasicBlockEntryCountSerializer::SaveAsJson(
    const EntryCountMap& entry_count_map, const FilePath& path) {
  DCHECK(!path.empty());
  file_util::ScopedFILE file(file_util::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Failed to open " << path.value() << " for reading.";
    return false;
  }

  if (!SaveAsJson(entry_count_map, file.get())) {
    LOG(ERROR) << "Failed to write JSON data to " << path.value() << ".";
    return false;
  }

  return true;
}

bool BasicBlockEntryCountSerializer::LoadFromJson(
    const FilePath& path, EntryCountMap* entry_count_map) {
  DCHECK(entry_count_map != NULL);
  DCHECK(!path.empty());

  std::string json_string;
  if (!file_util::ReadFileToString(path, &json_string)) {
    LOG(ERROR) << "Failed to read '" << path.value() << "'.";
    return false;
  }

  base::JSONReader json_reader;
  std::string error_msg;
  scoped_ptr<base::Value> json_value(
      json_reader.ReadAndReturnError(json_string, true, NULL, &error_msg));
  if (json_value.get() == NULL) {
    LOG(ERROR) << "Failed to parse '" << path.value() << "' as JSON ("
               << error_msg << ").";
    return false;
  }

  if (!PopulateFromJsonValue(json_value.get(), entry_count_map))
    return false;

  return true;
}

bool BasicBlockEntryCountSerializer::PopulateFromJsonValue(
    const base::Value* json_value, EntryCountMap* entry_count_map) {
  DCHECK(json_value != NULL);
  DCHECK(entry_count_map != NULL);

  entry_count_map->clear();

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
    if (!ReadEntryCount(dict_value, entry_count_map)) {
      // ReadEntryCount() has already logged the error.
      return false;
    }
  }

  return true;
}

}  // namespace grinder
