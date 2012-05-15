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

#include "syzygy/reorder/reorderer.h"

#include "base/file_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/values.h"
#include "base/json/json_reader.h"
#include "base/json/string_escape.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace reorder {

using block_graph::BlockGraph;
using trace::parser::Parser;

namespace {

// Serializes a block list to JSON.
bool OutputBlockList(size_t section_id,
                     const Reorderer::Order::BlockList& blocks,
                     core::JSONFileWriter* json_file) {
  DCHECK(json_file != NULL);

  if (!json_file->OpenDict() ||
      !json_file->OutputKey("section_id") ||
      !json_file->OutputInteger(section_id) ||
      !json_file->OutputKey("blocks") ||
      !json_file->OpenList()) {
    return false;
  }

  for (size_t i = 0; i < blocks.size(); ++i) {
    // Output the block address.
    if (!json_file->OutputInteger(blocks[i]->addr().value()))
      return false;

    // If we're pretty printing, output a comment with some detail about the
    // block.
    if (json_file->pretty_print()) {
      std::string comment = base::StringPrintf(
          "%s(%s)",
          BlockGraph::BlockTypeToString(blocks[i]->type()),
          blocks[i]->name().c_str());
      if (!json_file->OutputTrailingComment(comment.c_str()))
        return false;
    }
  }

  return json_file->CloseList() && json_file->CloseDict();
}

}  // namespace

Reorderer::Reorderer(const FilePath& module_path,
                     const FilePath& instrumented_path,
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

void Reorderer::OnProcessStarted(base::Time time,
                                 DWORD process_id,
                                 const TraceSystemInfo* data) {
  // We ignore these events and infer/pretend that a process we're interested
  // in has started when it begins to generate trace events.
}

void Reorderer::OnProcessEnded(base::Time time, DWORD process_id) {
  // Notify the order generator.
  if (!order_generator_->OnProcessEnded(process_id, UniqueTime(time))) {
    parser_.set_error_occurred(true);
    return;
  }

  // Cleanup the local record for process_id.
  ignore_result(matching_process_ids_.erase(process_id));
}

// CallTraceEvents implementation.
void Reorderer::OnFunctionEntry(base::Time time,
                                DWORD process_id,
                                DWORD thread_id,
                                const TraceEnterExitEventData* data) {
  DCHECK(data != NULL);

  const BlockGraph::Block* block = playback_.FindFunctionBlock(process_id,
                                                               data->function);

  if (block == NULL) {
    parser_.set_error_occurred(true);
    return;
  }

  // Get the actual time of the call. We ignore ticks_ago for now, as the
  // low-resolution and rounding can cause inaccurate relative timings. We
  // simply rely on the buffer ordering (via UniqueTime's internal counter)
  // to maintain relative ordering. For future reference, ticks_ago are in
  // milliseconds, according to MSDN.
  UniqueTime entry_time(time);

  // If this is the first call of interest by a given process, send an
  // OnProcessStarted event.
  if (matching_process_ids_.insert(process_id).second) {
    if (!order_generator_->OnProcessStarted(process_id, entry_time)) {
      parser_.set_error_occurred(true);
      return;
    }
  }

  ++code_block_entry_events_;
  if (!order_generator_->OnCodeBlockEntry(block,
                                          block->addr(),
                                          process_id,
                                          thread_id,
                                          entry_time)) {
    parser_.set_error_occurred(true);
    return;
  }
}

void Reorderer::OnFunctionExit(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceEnterExitEventData* data) {
  // We currently don't care about TraceExit events.
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

void Reorderer::OnProcessAttach(base::Time time,
                                DWORD process_id,
                                DWORD thread_id,
                                const TraceModuleData* data) {
  // We don't do anything with these events.
}

void Reorderer::OnProcessDetach(base::Time time,
                                DWORD process_id,
                                DWORD thread_id,
                                const TraceModuleData* data) {
  // We don't do anything with these events.
}

void Reorderer::OnThreadAttach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
  // We don't do anything with these events.
}

void Reorderer::OnThreadDetach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
  // We don't do anything with these events.
}

void Reorderer::OnInvocationBatch(base::Time time,
                                  DWORD process_id,
                                  DWORD thread_id,
                                  size_t num_batches,
                                  const TraceBatchInvocationInfo* data) {
  // We don't do anything with these events.
}

bool Reorderer::Order::SerializeToJSON(const PEFile& pe,
                                       const FilePath &path,
                                       bool pretty_print) const {
  file_util::ScopedFILE file(file_util::OpenFile(path, "wb"));
  if (file.get() == NULL)
    return false;
  core::JSONFileWriter json_file(file.get(), pretty_print);
  return SerializeToJSON(pe, &json_file);
}

bool Reorderer::Order::SerializeToJSON(const PEFile& pe,
                                       core::JSONFileWriter* json_file) const {
  DCHECK(json_file != NULL);

  // Open the main dictionary and the metadata dictionary.
  if (!json_file->OutputComment(comment.c_str()) ||
      !json_file->OpenDict() ||
      !json_file->OutputKey("metadata")) {
    return false;
  }

  // Output metadata.
  PEFile::Signature orig_sig;
  pe.GetSignature(&orig_sig);
  pe::Metadata metadata;
  if (!metadata.Init(orig_sig) ||
      !metadata.SaveToJSON(json_file)) {
    return false;
  }

  // Open list of sections.
  if (!json_file->OutputKey("sections") ||
      !json_file->OpenList()) {
    return false;
  }

  // Output the individual block lists.
  BlockListMap::const_iterator it = section_block_lists.begin();
  for (; it != section_block_lists.end(); ++it) {
    if (it->second.size() == 0)
      continue;

    // Output a comment with the section name, and output the section
    // order info.
    std::string comment = pe.GetSectionName(it->first);
    comment = StringPrintf("section_name = \"%s\".", comment.c_str());
    if (!json_file->OutputComment(comment.c_str()) ||
        !OutputBlockList(it->first, it->second, json_file)) {
      return false;
    }
  }

  // Close the list of sections and the outermost dictionary.
  return json_file->CloseList() && json_file->CloseDict();
}

bool Reorderer::Order::LoadFromJSON(const PEFile& pe,
                                    const ImageLayout& image,
                                    const FilePath& path) {
  std::string file_string;
  if (!file_util::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string";
    return false;
  }

  scoped_ptr<Value> value(base::JSONReader::Read(file_string, false));
  if (value.get() == NULL || value->GetType() != Value::TYPE_DICTIONARY) {
    LOG(ERROR) << "Order file does not contain a valid JSON dictionary.";
  }
  const DictionaryValue* outer_dict =
      reinterpret_cast<const DictionaryValue*>(value.get());

  std::string metadata_key("metadata");
  std::string sections_key("sections");
  DictionaryValue* metadata_dict = NULL;
  ListValue* order = NULL;
  if (!outer_dict->GetDictionary(metadata_key, &metadata_dict) ||
      !outer_dict->GetList(sections_key, &order)) {
    LOG(ERROR) << "Order dictionary must contain 'metadata' and 'sections'.";
    return false;
  }

  // Load the metadata from the order file, and ensure it is consistent with
  // the signature of the module the ordering is being applied to.
  pe::Metadata metadata;
  PEFile::Signature pe_sig;
  pe.GetSignature(&pe_sig);
  if (!metadata.LoadFromJSON(*metadata_dict) ||
      !metadata.IsConsistent(pe_sig))
    return false;

  section_block_lists.clear();

  // Iterate through the elements of the list. They should each be dictionaries
  // representing a single section.
  ListValue::iterator section_it = order->begin();
  for (; section_it != order->end(); ++section_it) {
    if ((*section_it) == NULL ||
        (*section_it)->GetType() != Value::TYPE_DICTIONARY) {
      LOG(ERROR) << "Order file list does not contain dictionaries.";
      return false;
    }
    const DictionaryValue* section =
        reinterpret_cast<const DictionaryValue*>(*section_it);

    std::string section_id_key("section_id");
    std::string blocks_key("blocks");
    int section_id_int = 0;
    ListValue* blocks = NULL;
    if (!section->GetInteger(section_id_key, &section_id_int) ||
        !section->GetList(blocks_key, &blocks)) {
      LOG(ERROR) << "Section dictionary must contain integer 'section_id' and "
                 << "list 'blocks'.";
      return false;
    }
    size_t section_id = section_id_int;
    DCHECK(blocks != NULL);

    if (section_block_lists.find(section_id) != section_block_lists.end()) {
      LOG(ERROR) << "Section " << section_id << " redefined.";
      return false;
    }

    if (blocks->GetSize() == 0)
      continue;

    BlockList& block_list = section_block_lists[section_id];
    ListValue::iterator block_it = blocks->begin();
    for (; block_it != blocks->end(); ++block_it) {
      int address = 0;
      if ((*block_it) == NULL || !(*block_it)->GetAsInteger(&address)) {
        LOG(ERROR) << "'blocks' must be a list of integers.";
        return false;
      }
      RelativeAddress rva(address);

      const BlockGraph::Block* block = image.blocks.GetBlockByAddress(rva);
      if (block == NULL) {
        LOG(ERROR) << "Block address not found in decomposed image: "
                   << address;
        return false;
      }
      if (block->section() != section_id) {
        LOG(ERROR) << "Block at address " << address << " belongs to section "
                   << block->section() << " and not section " << section_id;
        return false;
      }
      block_list.push_back(block);
    }
  }

  return true;
}

bool Reorderer::Order::GetOriginalModulePath(const FilePath& path,
                                             FilePath* module) {
  std::string file_string;
  if (!file_util::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string.";
    return false;
  }

  scoped_ptr<Value> value(base::JSONReader::Read(file_string, false));
  if (value.get() == NULL || value->GetType() != Value::TYPE_DICTIONARY) {
    LOG(ERROR) << "Order file does not contain a valid JSON dictionary.";
    return false;
  }
  const DictionaryValue* outer_dict =
      reinterpret_cast<const DictionaryValue*>(value.get());

  std::string metadata_key("metadata");
  DictionaryValue* metadata_dict = NULL;
  if (!outer_dict->GetDictionary(metadata_key, &metadata_dict)) {
    LOG(ERROR) << "Order dictionary must contain 'metadata'.";
    return false;
  }

  pe::Metadata metadata;
  if (!metadata.LoadFromJSON(*metadata_dict))
    return false;

  *module = FilePath(metadata.module_signature().path);

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
