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

#include "syzygy/reorder/reorderer.h"

#include "base/file_util.h"
#include "base/values.h"
#include "base/json/json_reader.h"
#include "base/json/string_escape.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_utils.h"

namespace reorder {

using block_graph::BlockGraph;
using trace::parser::Parser;
using base::ListValue;
using base::DictionaryValue;
using base::Value;

namespace {

const char kCommentKey[] = "comment";
const char kMetadataKey[] = "metadata";
const char kSectionsKey[] = "sections";
const char kSectionIdKey[] = "id";
const char kSectionNameKey[] = "name";
const char kSectionCharacteristicsKey[] = "characteristics";
const char kBlocksKey[] = "blocks";

bool OutputTrailingBlockComment(const BlockGraph::Block* block,
                                core::JSONFileWriter* json_file) {
  DCHECK(block != NULL);
  DCHECK(json_file != NULL);

  if (!json_file->pretty_print())
    return true;

  std::string comment = base::StringPrintf(
      "%s(%s)",
      BlockGraph::BlockTypeToString(block->type()),
      block->name().c_str());

  if (!json_file->OutputTrailingComment(comment))
    return false;

  return true;
}

bool OutputBlockSpec(const Reorderer::Order::BlockSpec& block_spec,
                     core::JSONFileWriter* json_file) {
  // TODO(rogerm): Stop referring to block->addr() and take the address space
  //     as an input parameter.
  DCHECK(json_file != NULL);
  // TODO(rogerm): Flesh out support for synthesizing new blocks.
  DCHECK(block_spec.block != NULL);

  // If no basic-block RVAs are given then the entire block is to be
  // used and we can just just the block address.
  if (block_spec.basic_block_offsets.empty()) {
    if (!json_file->OutputInteger(block_spec.block->addr().value()))
      return false;
    if (!OutputTrailingBlockComment(block_spec.block, json_file))
      return false;
    return true;
  }

  // Otherwise, we output a pair (two element list) comprising the block
  // address and the list of basic-block RVAs.

  // Open the outer list.
  if (!json_file->OpenList())
    return false;

  // Output the block address.
  if (!json_file->OutputInteger(block_spec.block->addr().value()) ||
      !OutputTrailingBlockComment(block_spec.block, json_file)) {
    return false;
  }

  // Open the inner list.
  if (!json_file->OpenList())
    return false;

  // Output the basic block RVAs.
  Reorderer::Order::OffsetVector::const_iterator it =
      block_spec.basic_block_offsets.begin();
  for (; it != block_spec.basic_block_offsets.end(); ++it) {
    if (!json_file->OutputInteger(*it))
      return false;
  }

  // Close the inner list.
  if (!json_file->CloseList())
    return false;

  // Close the outer list.
  if (!json_file->CloseList())
    return false;

  return true;
}

// Serializes a block list to JSON.
bool OutputSectionSpec(const Reorderer::Order::SectionSpec& section_spec,
                       core::JSONFileWriter* json_file) {
  DCHECK(json_file != NULL);

  // Open the section specification dictionary.
  if (!json_file->OpenDict())
    return false;

  // If the section has an ID in the original image, output the ID.
  if (section_spec.id != Reorderer::Order::SectionSpec::kNewSectionId) {
    if (!json_file->OutputKey(kSectionIdKey) ||
        !json_file->OutputInteger(section_spec.id)) {
      return false;
    }
  }

  // Output the section metadata.
  if (!json_file->OutputKey(kSectionNameKey) ||
      !json_file->OutputString(section_spec.name) ||
      !json_file->OutputKey(kSectionCharacteristicsKey) ||
      !json_file->OutputInteger(section_spec.characteristics)) {
    return false;
  }

  // Open the block spec list.
  if (!json_file->OutputKey(kBlocksKey) ||
      !json_file->OpenList()) {
    return false;
  }

  // Output each of the block specifications.
  Reorderer::Order::BlockSpecVector::const_iterator it =
      section_spec.blocks.begin();
  for (; it != section_spec.blocks.end(); ++it) {
    if (!OutputBlockSpec(*it, json_file))
      return false;
  }

  // Close the block spec list.
  if (!json_file->CloseList())
    return false;

  // Close the section spec dictionary.
  if (!json_file->CloseDict())
    return false;

  return true;
}

bool LoadBlockSpec(const pe::ImageLayout& image,
                   const Value* block_value,
                   Reorderer::Order::BlockSpec* block_spec) {
  DCHECK(block_value != NULL);
  DCHECK(block_spec != NULL);

  block_spec->block = NULL;
  block_spec->basic_block_offsets.clear();

  // If the block value is a single integer, then we use the entire block.
  // Otherwise, we evaluate the value as a pair (represented as a list)
  // where the first element is the address and the second element is a list
  // of basic-block RVAs.
  int address = 0;
  const ListValue* rva_list = NULL;
  if (!block_value->GetAsInteger(&address)) {
    const ListValue* pair = NULL;
    if (!block_value->GetAsList(&pair) ||
        !pair->GetInteger(0, &address) ||
        !pair->GetList(1, &rva_list)) {
      LOG(ERROR) << "Invalid entry for block specification.";
      return false;
    }
  }

  // Resolve the referenced block.
  core::RelativeAddress rva(address);
  const BlockGraph::Block* block = image.blocks.GetBlockByAddress(rva);
  if (block == NULL) {
    LOG(ERROR) << "Block address not found in decomposed image: "
                << address;
    return false;
  }

  // Read in the basic_block offsets.
  bool seen_end_block = false;
  if (rva_list != NULL && !rva_list->empty()) {
    block_spec->basic_block_offsets.reserve(rva_list->GetSize());
    for (size_t i = 0; i < rva_list->GetSize(); ++i) {
      int offset = 0;
      if (!rva_list->GetInteger(i, &offset)) {
        LOG(ERROR) << "Unexpected value for basic-block offset #" << i
                   << " of " << address << " [" << block->name() << "].";
        block_spec->basic_block_offsets.clear();
        return false;
      }
      if (offset < 0 ||
          static_cast<BlockGraph::Size>(offset) > block->size()) {
        LOG(ERROR) << "Offset " << offset << " falls outside block range [0-"
                   << block->size() << "] for " << block->name();
        return false;
      }

      // The basic-end block must be last in the block specification. The
      // block builder will catch this error but we can meaningfully catch this
      // earlier and avoid a lot of computation for nothing.
      if (static_cast<BlockGraph::Size>(offset) == block->size()) {
        seen_end_block = true;
      } else if (seen_end_block) {
        LOG(ERROR) << "Encountered basic-end block that is not last in the "
                   << "specified ordering.";
        return false;
      }
      block_spec->basic_block_offsets.push_back(offset);
    }
  }

  block_spec->block = block;
  return true;
}

bool LoadSectionSpec(const pe::ImageLayout& image,
                     const DictionaryValue* section_value,
                     Reorderer::Order::SectionSpec* section_spec,
                     std::set<size_t>* seen_section_ids) {
  DCHECK(section_value != NULL);
  DCHECK(section_spec != NULL);
  DCHECK(seen_section_ids != NULL);

  // Some keys we'll refer to multiple times below.
  const std::string section_id_key(kSectionIdKey);
  const std::string section_name_key(kSectionNameKey);
  const std::string section_characteristics_key(kSectionCharacteristicsKey);
  const std::string blocks_key(kBlocksKey);

  // Get the section id, if given.
  int tmp_section_id = Reorderer::Order::SectionSpec::kNewSectionId;
  if (section_value->HasKey(section_id_key) &&
      !section_value->GetInteger(section_id_key, &tmp_section_id)) {
    LOG(ERROR) << "Invalid value for " << section_id_key << ".";
    return false;
  }

  // Lookup the original section by id, if the id was given. Populate the
  // section metadata based on the original section info. The other keys
  // will be inspected below to see if any of the metadata needs to be
  // over-ridden.
  section_spec->id = tmp_section_id;
  if (section_spec->id != Reorderer::Order::SectionSpec::kNewSectionId) {
    // Lookup the section in the original image layout.
    if (section_spec->id < 0 || section_spec->id > image.sections.size()) {
      LOG(ERROR) << "Invalid section id: " << section_spec->id << ".";
      return false;
    }

    // Make sure this section id does not already exist.
    if (!seen_section_ids->insert(section_spec->id).second) {
      LOG(ERROR) << "Section ID " << section_spec->id << " redefined.";
      return false;
    }

    // Copy the metadata into the section spec.
    section_spec->name = image.sections[section_spec->id].name;
    section_spec->characteristics =
        image.sections[section_spec->id].characteristics;
  }

  // Possibly over-ride the section name.
  if (section_value->HasKey(section_name_key) &&
      !section_value->GetString(section_name_key, &section_spec->name)) {
    LOG(ERROR) << "Invalid value for " << section_name_key << ".";
    return false;
  }

  // Make sure we've got a section name. This may have come from either the
  // the original image (via the section id) or explicitly from the section
  // name key.
  if (section_spec->name.empty()) {
    LOG(ERROR) << "Missing a value for the section name. Either a valid "
               << section_id_key << " or valid " << section_name_key
               << " is required.";
    return false;
  }

  // Possibly over-ride the section characteristics. The characteristics are
  // required if the section was not given by id.
  if (section_spec->id == Reorderer::Order::SectionSpec::kNewSectionId ||
      section_value->HasKey(section_characteristics_key)) {
    int tmp_characteristics = 0;
    if (!section_value->GetInteger(section_characteristics_key,
                                   &tmp_characteristics)) {
      LOG(ERROR) << "Missing or invalid value for "
                 << section_characteristics_key << ".";
      return false;
    }
    section_spec->characteristics = tmp_characteristics;
  }

  // Get the list of block specifications.
  const ListValue* blocks = NULL;
  if (!section_value->GetList(blocks_key, &blocks)) {
    LOG(ERROR) << "Invalid or missing value for " << blocks_key << ".";
    return false;
  }

  if (!blocks->empty()) {
    // Populate the block spec vector.
    section_spec->blocks.resize(blocks->GetSize());
    for (size_t block_idx = 0; block_idx != blocks->GetSize(); ++block_idx) {
      const Value* block_value = NULL;
      if (!blocks->Get(block_idx, &block_value)) {
        LOG(ERROR) << "Failed to access item " << block_idx << ".";
        return false;
      }

      if (!LoadBlockSpec(image, block_value, &section_spec->blocks[block_idx]))
        return false;
    }
  }

  return true;
}

}  // namespace

const size_t Reorderer::Order::SectionSpec::kNewSectionId = ~1;

Reorderer::Reorderer(const base::FilePath& module_path,
                     const base::FilePath& instrumented_path,
                     const TraceFileList& trace_files,
                     Flags flags)
    : playback_(module_path, instrumented_path, trace_files),
      flags_(flags),
      code_block_entry_events_(0),
      order_generator_(NULL) {
}

Reorderer::~Reorderer() {
}

bool Reorderer::Reorder(OrderGenerator* order_generator,
                        Order* order,
                        PEFile* pe_file,
                        ImageLayout* image) {
  DCHECK(order_generator != NULL);
  DCHECK(order != NULL);

  DCHECK(order_generator_ == NULL);
  order_generator_ = order_generator;

  bool success = ReorderImpl(order, pe_file, image);

  order_generator_ = NULL;

  return success;
}

bool Reorderer::ReorderImpl(Order* order,
                            PEFile* pe_file,
                            ImageLayout* image) {
  DCHECK(order != NULL);
  DCHECK(order_generator_ != NULL);

  if (!parser_.Init(this)) {
    LOG(ERROR) << "Failed to initialize call trace parser.";
    return false;
  }

  if (!playback_.Init(pe_file, image, &parser_))
    return false;

  if (playback_.trace_files().size() > 0) {
    LOG(INFO) << "Processing trace events.";
    if (!parser_.Consume())
      return false;

    if (code_block_entry_events_ == 0) {
      LOG(ERROR) << "No events originated from the given instrumented DLL.";
      return false;
    }
  }

  if (!CalculateReordering(order))
    return false;

  return true;
}

bool Reorderer::CalculateReordering(Order* order) {
  DCHECK(order != NULL);
  DCHECK(order_generator_ != NULL);

  LOG(INFO) << "Calculating new order.";
  if (!order_generator_->CalculateReordering(*playback_.pe_file(),
                                             *playback_.image(),
                                             (flags_ & kFlagReorderCode) != 0,
                                             (flags_ & kFlagReorderData) != 0,
                                             order))
    return false;

  order->comment = base::StringPrintf("Generated using the %s.",
                                      order_generator_->name().c_str());

  return true;
}

void Reorderer::OnProcessStarted(
    base::Time time, DWORD process_id, const TraceSystemInfo* data) {
  UniqueTime entry_time(time);

  if (!order_generator_->OnProcessStarted(process_id, entry_time)) {
    parser_.set_error_occurred(true);
    return;
  }
}

void Reorderer::OnProcessEnded(base::Time time, DWORD process_id) {
  // Notify the order generator.
  if (!order_generator_->OnProcessEnded(process_id, UniqueTime(time))) {
    parser_.set_error_occurred(true);
    return;
  }
}

// CallTraceEvents implementation.
void Reorderer::OnFunctionEntry(base::Time time,
                                DWORD process_id,
                                DWORD thread_id,
                                const TraceEnterExitEventData* data) {
  DCHECK(data != NULL);

  bool error = false;
  const BlockGraph::Block* block = playback_.FindFunctionBlock(process_id,
                                                               data->function,
                                                               &error);

  // Handle the error if any occurred.
  if (error) {
    LOG(ERROR) << "Playback::FindFunctionBlock failed.";
    parser_.set_error_occurred(true);
    return;
  }

  // If no block was found then we simply ignore the event.
  if (block == NULL)
    return;

  // Get the time of the call. Since batched function calls come in with the
  // same time stamp, we rely on their relative ordering and UniqueTime's
  // incrementing ID to maintain relative order.
  UniqueTime entry_time(time);

  ++code_block_entry_events_;
  if (!order_generator_->OnCodeBlockEntry(block,
                                          block->addr(),
                                          process_id,
                                          thread_id,
                                          entry_time)) {
    LOG(ERROR) << order_generator_->name() << "::OnCodeBlockEntry failed.";
    parser_.set_error_occurred(true);
    return;
  }
}

void Reorderer::OnBatchFunctionEntry(base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceBatchEnterData* data) {
  // Explode the batch event into individual function entry events.
  TraceEnterExitEventData new_data = {};
  for (size_t i = 0; i < data->num_calls; ++i) {
    new_data.function = data->calls[i].function;
    OnFunctionEntry(time, process_id, thread_id, &new_data);
  }
}

bool Reorderer::Order::SerializeToJSON(const PEFile& pe,
                                       const base::FilePath &path,
                                       bool pretty_print) const {
  base::ScopedFILE file(base::OpenFile(path, "wb"));
  if (file.get() == NULL)
    return false;
  core::JSONFileWriter json_file(file.get(), pretty_print);
  return SerializeToJSON(pe, &json_file);
}

bool Reorderer::Order::SerializeToJSON(const PEFile& pe,
                                       core::JSONFileWriter* json_file) const {
  DCHECK(json_file != NULL);

  // Open the top-level dictionary and the metadata dictionary.
  if (!json_file->OpenDict())
    return false;

  // Output the filecomment.
  if (!json_file->OutputKey(kCommentKey) ||
      !json_file->OutputString(comment)) {
    return false;
  }

  // Output metadata.
  PEFile::Signature orig_sig;
  pe.GetSignature(&orig_sig);
  pe::Metadata metadata;
  if (!metadata.Init(orig_sig) ||
      !json_file->OutputKey(kMetadataKey) ||
      !metadata.SaveToJSON(json_file)) {
    return false;
  }

  // Open list of sections.
  if (!json_file->OutputKey(kSectionsKey) ||
      !json_file->OpenList()) {
    return false;
  }

  // Output the individual block lists.
  SectionSpecVector::const_iterator it = sections.begin();
  for (; it != sections.end(); ++it) {
    const SectionSpec& section_spec = *it;
    if (section_spec.blocks.empty())
      continue;

    if (!OutputSectionSpec(section_spec, json_file))
      return false;
  }

  // Close the list of sections.
  if (!json_file->CloseList())
    return false;

  // Close the outermost dictionary.
  if (!json_file->CloseDict())
    return false;

  return true;
}

bool Reorderer::Order::LoadFromJSON(const PEFile& pe,
                                    const ImageLayout& image,
                                    const base::FilePath& path) {
  std::string file_string;
  if (!base::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string";
    return false;
  }

  // Read in the JSON file. It should be a dictionary.
  const DictionaryValue* outer_dict = NULL;
  scoped_ptr<Value> value(base::JSONReader::Read(file_string));
  if (value.get() == NULL || !value->GetAsDictionary(&outer_dict)) {
    LOG(ERROR) << "Order file does not contain a valid JSON dictionary.";
    return false;
  }

  // Load the metadata from the order file, and ensure it is consistent with
  // the signature of the module the ordering is being applied to.
  pe::Metadata metadata;
  PEFile::Signature pe_sig;
  pe.GetSignature(&pe_sig);
  const DictionaryValue* metadata_dict = NULL;
  if (!outer_dict->GetDictionary(kMetadataKey, &metadata_dict) ||
      !metadata.LoadFromJSON(*metadata_dict) ||
      !metadata.IsConsistent(pe_sig)) {
    LOG(ERROR) << "Missing, invalid, or inconsistent " << kMetadataKey << ".";
    return false;
  }

  // Load the comments field.
  if (outer_dict->HasKey(kCommentKey) &&
      !outer_dict->GetString(kCommentKey, &comment)) {
    LOG(ERROR) << "Invalid " << kCommentKey << " value. Must be a string.";
    return false;
  }

  // Grab the sections list.
  const ListValue* order = NULL;
  if (!outer_dict->GetList(kSectionsKey, &order)) {
    LOG(ERROR) << "Missing or invalid " << kSectionsKey << ".";
    return false;
  }

  // Allocate the expected number of sections.
  sections.clear();

  // Iterate through the elements of the list. They should each be dictionaries
  // representing a single section. We'll also track the sections descriptions
  // we have already seen.
  std::set<size_t> seen_section_ids;
  sections.resize(order->GetSize());
  for (size_t index = 0; index < order->GetSize(); ++index) {
    const DictionaryValue* section = NULL;
    if (!order->GetDictionary(index, &section)) {
      LOG(ERROR) << "Item " << index << "of " << kSectionsKey
                 << " list is not a dictionary.";
      return false;
    }

    if (!LoadSectionSpec(image, section, &sections[index], &seen_section_ids))
      return false;
  }

  return true;
}

bool Reorderer::Order::GetOriginalModulePath(const base::FilePath& path,
                                             base::FilePath* module) {
  std::string file_string;
  if (!base::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string.";
    return false;
  }

  scoped_ptr<Value> value(base::JSONReader::Read(file_string));
  if (value.get() == NULL || value->GetType() != Value::TYPE_DICTIONARY) {
    LOG(ERROR) << "Order file does not contain a valid JSON dictionary.";
    return false;
  }
  const DictionaryValue* outer_dict =
      reinterpret_cast<const DictionaryValue*>(value.get());

  std::string metadata_key("metadata");
  const DictionaryValue* metadata_dict = NULL;
  if (!outer_dict->GetDictionary(metadata_key, &metadata_dict)) {
    LOG(ERROR) << "Order dictionary must contain 'metadata'.";
    return false;
  }

  pe::Metadata metadata;
  if (!metadata.LoadFromJSON(*metadata_dict))
    return false;

  *module = base::FilePath(metadata.module_signature().path);

  return true;
}

Reorderer::UniqueTime::UniqueTime()
    : time_(),
      id_(0) {
}

Reorderer::UniqueTime::UniqueTime(const UniqueTime& other)
    : time_(other.time_),
      id_(other.id_) {
}

Reorderer::UniqueTime::UniqueTime(const base::Time& time)
    : time_(time),
      id_(next_id_++) {
}

Reorderer::UniqueTime& Reorderer::UniqueTime::operator=(const UniqueTime& rhs) {
  time_ = rhs.time_;
  id_ = rhs.id_;
  return *this;
}

int Reorderer::UniqueTime::compare(const UniqueTime& rhs) const {
  if (time_ < rhs.time_)
    return -1;
  if (time_ > rhs.time_)
    return 1;
  if (id_ < rhs.id_)
    return -1;
  if (id_ > rhs.id_)
    return 1;
  return 0;
}

size_t Reorderer::UniqueTime::next_id_ = 0;

}  // namespace reorder
