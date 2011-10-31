// Copyright 2011 Google Inc.
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
#include "base/json/json_reader.h"
#include "base/json/string_escape.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/values.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace {

using core::BlockGraph;
using reorder::Reorderer;
using call_trace::parser::Parser;

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
          core::BlockGraph::kBlockType[blocks[i]->type()],
          blocks[i]->name());
      if (!json_file->OutputTrailingComment(comment.c_str()))
        return false;
    }
  }

  return json_file->CloseList() && json_file->CloseDict();
}

}  // namespace

namespace reorder {

Reorderer::Reorderer(const FilePath& module_path,
                     const FilePath& instrumented_path,
                     const TraceFileList& trace_files,
                     Flags flags)
    : module_path_(module_path),
      instrumented_path_(instrumented_path),
      trace_files_(trace_files),
      flags_(flags),
      code_block_entry_events_(0),
      order_generator_(NULL),
      pe_(NULL),
      image_(NULL),
      parser_(NULL) {
}

Reorderer::~Reorderer() {
}

bool Reorderer::Reorder(OrderGenerator* order_generator,
                        Order* order,
                        PEFile* pe_file,
                        ImageLayout* image) {
  DCHECK(order_generator != NULL);
  DCHECK(order != NULL);

  Parser parser;
  if (!parser.Init(this)) {
    LOG(ERROR) << "Failed to initialize call trace parser.";
    return false;
  }

  DCHECK(order_generator_ == NULL);
  DCHECK(pe_ == NULL);
  DCHECK(image_ == NULL);
  DCHECK(parser_ == NULL);

  order_generator_ = order_generator;
  pe_ = pe_file;
  image_ = image;
  parser_ = &parser;

  bool success = ReorderImpl(order);

  order_generator_ = NULL;
  pe_ = NULL;
  image_ = NULL;
  parser_ = NULL;

  return success;
}

bool Reorderer::ReorderImpl(Order* order) {
  DCHECK(order_generator_ != NULL);
  DCHECK(pe_ != NULL);
  DCHECK(image_ != NULL);
  DCHECK(parser_ != NULL);

  // Validate the instrumented module, and extract the signature of the original
  // module it was built from.
  pe::PEFile::Signature orig_signature;
  if (!ValidateInstrumentedModuleAndParseSignature(&orig_signature))
    return false;

  // If the input DLL path is empty, use the inferred one from the
  // instrumented module.
  if (module_path_.empty()) {
    LOG(INFO) << "Inferring input DLL path from instrumented module: "
              << orig_signature.path;
    module_path_ = FilePath(orig_signature.path);
  }

  LOG(INFO) << "Reading input DLL.";
  if (!pe_->Init(module_path_)) {
    LOG(ERROR) << "Unable to read input image: " << module_path_.value();
    return false;
  }
  pe::PEFile::Signature input_signature;
  pe_->GetSignature(&input_signature);

  // Validate that the input DLL signature matches the original signature
  // extracted from the instrumented module.
  if (!orig_signature.IsConsistent(input_signature)) {
    LOG(ERROR) << "Instrumented module metadata does not match input module.";
    return false;
  }

  // Open the log files. We do this before running the decomposer as if these
  // fail we'll have wasted a lot of time!

  for (TraceFileIter i = trace_files_.begin(); i < trace_files_.end(); ++i) {
    const FilePath& trace_path = *i;
    LOG(INFO) << "Reading " << trace_path.value() << ".";
    if (!parser_->OpenTraceFile(trace_path)) {
      LOG(ERROR) << "Unable to open ETW log file: " << trace_path.value();
      return false;
    }
  }

  // Decompose the DLL to be reordered. This will let us map call-trace events
  // to actual Blocks.
  LOG(INFO) << "Decomposing input image.";
  Decomposer decomposer(*pe_);
  if (!decomposer.Decompose(image_)) {
    LOG(ERROR) << "Unable to decompose input image: " << module_path_.value();
    return false;
  }

  // Parse the logs.
  if (trace_files_.size() > 0) {
    LOG(INFO) << "Processing trace events.";
    if (!parser_->Consume()) {
      LOG(ERROR) << "Failed to consume call trace events.";
      return false;
    }

    if (code_block_entry_events_ == 0) {
      LOG(ERROR) << "No events originated from the given instrumented DLL.";
      return false;
    }
  }

  LOG(INFO) << "Calculating new order.";
  if (!order_generator_->CalculateReordering(*pe_,
                                             *image_,
                                             (flags_ & kFlagReorderCode) != 0,
                                             (flags_ & kFlagReorderData) != 0,
                                             order))
    return false;

  order->comment = base::StringPrintf("Generated using the %s.",
                                      order_generator_->name().c_str());

  return true;
}

bool Reorderer::ValidateInstrumentedModuleAndParseSignature(
    pe::PEFile::Signature* orig_signature) {
  DCHECK(orig_signature != NULL);

  pe::PEFile pe_file;
  if (!pe_file.Init(instrumented_path_)) {
    LOG(ERROR) << "Unable to parse instrumented module: "
               << instrumented_path_.value();
    return false;
  }
  pe_file.GetSignature(&instr_signature_);

  // Load the metadata from the PE file. Validate the toolchain version and
  // return the original module signature.
  pe::Metadata metadata;
  if (!metadata.LoadFromPE(pe_file))
    return false;
  *orig_signature = metadata.module_signature();

  if (!common::kSyzygyVersion.IsCompatible(metadata.toolchain_version())) {
    LOG(ERROR) << "Module was instrumented with an incompatible version of "
               << "the toolchain: " << instrumented_path_.value();
    return false;
  }

  return true;
}

bool Reorderer::MatchesInstrumentedModuleSignature(
    const ModuleInformation& module_info) const {
  // On Windows XP gathered traces, only the module size is non-zero.
  if (module_info.image_checksum == 0 && module_info.time_date_stamp == 0) {
    // If the size matches, then check that the names fit.
    if (instr_signature_.module_size != module_info.module_size)
      return false;

    FilePath base_name = instrumented_path_.BaseName();
    return (module_info.image_file_name.rfind(base_name.value()) !=
        std::wstring::npos);
  } else {
    // On Vista and greater, we can check the full module signature.
    return (instr_signature_.module_checksum == module_info.image_checksum &&
        instr_signature_.module_size == module_info.module_size &&
        instr_signature_.module_time_date_stamp == module_info.time_date_stamp);
  }
}

void Reorderer::OnProcessStarted(base::Time time, DWORD process_id) {
  // We ignore these events and infer/pretend that a process we're interested
  // in has started when it begins to generate trace events.
}

void Reorderer::OnProcessEnded(base::Time time, DWORD process_id) {
  ProcessSet::iterator process_it = matching_process_ids_.find(process_id);
  if (process_it != matching_process_ids_.end())
    matching_process_ids_.erase(process_it);
}

// CallTraceEvents implementation.
void Reorderer::OnFunctionEntry(base::Time time,
                                DWORD process_id,
                                DWORD thread_id,
                                const TraceEnterExitEventData* data) {
  // Resolve the module in which the called function resides.
  AbsoluteAddress64 function_address =
      reinterpret_cast<AbsoluteAddress64>(data->function);
  const ModuleInformation* module_info =
      parser_->GetModuleInformation(process_id, function_address);

  // Ignore event not belonging to the instrumented module of interest.
  if (module_info == NULL ||
      !MatchesInstrumentedModuleSignature(*module_info))
    return;

  // Get the block that this function call refers to. We can only instrument
  // 32-bit DLLs, so we're sure that the following address conversion is safe.
  RelativeAddress rva(
      static_cast<uint32>(function_address - module_info->base_address));
  const BlockGraph::Block* block =
      image_->blocks.GetBlockByAddress(rva);
  if (block == NULL) {
    LOG(ERROR) << "Unable to map " << rva << " to a block.";
    parser_->set_error_occurred(true);
    return;
  }
  if (block->type() != BlockGraph::CODE_BLOCK) {
    LOG(ERROR) << rva << " maps to a non-code block.";
    parser_->set_error_occurred(true);
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
      parser_->set_error_occurred(true);
      return;
    }
  }

  ++code_block_entry_events_;
  if (!order_generator_->OnCodeBlockEntry(block, rva,
                                          process_id,
                                          thread_id,
                                          entry_time)) {
    parser_->set_error_occurred(true);
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

      const BlockGraph::Block* block =
          image.blocks.GetBlockByAddress(rva);
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
    LOG(ERROR) << "Unable to read order file to string";
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
