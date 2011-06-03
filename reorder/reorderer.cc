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
#include "base/stringprintf.h"
#include "base/values.h"
#include "syzygy/pe/pe_file.h"

namespace {

using namespace reorder;

// Outputs @p indent spaces to @p file.
bool OutputIndent(FILE* file, int indent, bool pretty_print) {
  if (!pretty_print)
    return true;
  for (int i = 0; i < indent; ++i) {
    if (fputc(' ', file) == EOF)
      return false;
  }
  return true;
}

// Outputs an end of line, only if pretty-printing.
bool OutputLineEnd(FILE* file, bool pretty_print) {
  return !pretty_print || fputc('\n', file) != EOF;
}

// Outputs a JSON dictionary key, pretty-printed if so requested. Assumes that
// if pretty-printing, we're already on a new line. Also assumes that key is
// appropriately escaped if it contains invalid characters.
bool OutputKey(FILE* file, const char* key, int indent, bool pretty_print) {
  if (!OutputIndent(file, indent, pretty_print) ||
      fprintf(file, "\"%s\":", key) < 0 ||
      !OutputIndent(file, 1, pretty_print))
    return false;
  return true;
}

// Serializes a block list to JSON. If pretty-printing, assumes that we are
// already on a new line. Does not output a trailing new line.
bool OutputBlockList(FILE* file, size_t section_id,
                     const Reorderer::Order::BlockList& blocks,
                     int indent,
                     bool pretty_print) {
  DCHECK(file != NULL);

  // Output the section id.
  if (!OutputIndent(file, indent, pretty_print) ||
      fputc('{', file) == EOF ||
      !OutputLineEnd(file, pretty_print) ||
      !OutputKey(file, "section_id", indent + 2, pretty_print) ||
      fprintf(file, "%d,", section_id) < 0 ||
      !OutputLineEnd(file, pretty_print) ||
      // Output the sdtart of the block list.
      !OutputKey(file, "blocks", indent + 2, pretty_print) ||
      fputc('[', file) == EOF ||
      !OutputLineEnd(file, pretty_print)) {
    return false;
  }

  for (size_t i = 0; i < blocks.size(); ++i) {
    // Output the block address.
    if (!OutputIndent(file, indent + 4, pretty_print) ||
        fprintf(file, "%d", blocks[i]->addr().value()) < 0)
      return false;
    if (i < blocks.size() - 1 && fputc(',', file) == EOF)
      return false;

    // If we're pretty printing, output a comment with some detail about the
    // block.
    if (pretty_print) {
      if (fprintf(file, "  // ") < 0)
        return false;
      switch (blocks[i]->type()) {
        case BlockGraph::CODE_BLOCK:
          if (fprintf(file, "Code") < 0)
            return false;
          break;

        case BlockGraph::DATA_BLOCK:
          if (fprintf(file, "Data") < 0)
            return false;
          break;

        default:
          if (fprintf(file, "Other") < 0)
            return false;
          break;
      }
      if (fprintf(file, "(%s)\n", blocks[i]->name()) < 0)
        return false;
    }
  }
  // Close the block list.
  if (!OutputIndent(file, indent + 2, pretty_print) ||
      fputc(']', file) == EOF ||
      !OutputLineEnd(file, pretty_print) ||
      // Close the dictionary.
      !OutputIndent(file, indent, pretty_print) ||
      fputc('}', file) == EOF) {
    return false;
  }

  return true;
}

}  // namespace

namespace reorder {

Reorderer* Reorderer::consumer_ = NULL;

Reorderer::Reorderer(const FilePath& module_path,
                     const FilePath& instrumented_path,
                     const std::vector<FilePath>& trace_paths,
                     Flags flags)
    : module_path_(module_path),
      instrumented_path_(instrumented_path),
      trace_paths_(trace_paths),
      instr_checksum_(0),
      instr_size_(0),
      instr_time_date_stamp_(0),
      flags_(flags),
      code_block_entry_events_(0),
      consumer_errored_(false),
      order_generator_(NULL),
      image_(NULL) {
  DCHECK(consumer_ == NULL);
  if (consumer_ == NULL) {
    consumer_ = this;
    kernel_log_parser_.set_module_event_sink(this);
    call_trace_parser_.set_call_trace_event_sink(this);
  }
}

Reorderer::~Reorderer() {
  consumer_ = NULL;
}

bool Reorderer::Reorder(OrderGenerator* order_generator, Order* order) {
  DCHECK(order_generator != NULL);
  DCHECK(order != NULL);

  order_generator_ = order_generator;
  image_ = &order->image;

  bool success = ReorderImpl(order);

  order_generator_ = NULL;
  image_ = NULL;

  return success;
}

bool Reorderer::ReorderImpl(Order* order) {
  if (!ParseInstrumentedModuleSignature())
    return false;

  pe::PEFile input_module;
  if (!input_module.Init(module_path_)) {
    LOG(ERROR) << "Unable to read input image: " << module_path_.value();
    return false;
  }

  // Open the log files. We do this before running the decomposer as if these
  // fail we'll have wasted a lot of time!
  for (size_t i = 0; i < trace_paths_.size(); ++i) {
    std::wstring trace_path(trace_paths_[i].value());
    if (FAILED(OpenFileSession(trace_path.c_str()))) {
      LOG(ERROR) << "Unable to open ETW log file: " << trace_path;
      return false;
    }
  }

  // Decompose the DLL to be reordered. This will let us map call-trace events
  // to actual Blocks.
  Decomposer decomposer(input_module, module_path_);
  if (!decomposer.Decompose(image_, NULL, Decomposer::STANDARD_DECOMPOSITION)) {
    LOG(ERROR) << "Unable to decompose input image: " << module_path_.value();
    return false;
  }

  // Parse the logs.
  if (trace_paths_.size() > 0) {
    Consume();
    if (consumer_errored_)
      return false;
    if (code_block_entry_events_ == 0) {
      LOG(ERROR) << "No events originated from the given instrumented DLL.";
      return false;
    }
  }

  if (!order_generator_->CalculateReordering(*this, order))
    return false;

  order->comment = base::StringPrintf("Generated using the %s.",
                                      order_generator_->name().c_str());

  return true;
}

bool Reorderer::ParseInstrumentedModuleSignature() {
  pe::PEFile pe_file;
  if (!pe_file.Init(instrumented_path_)) {
    LOG(ERROR) << "Unable to parse instrumented module signature: "
               << instrumented_path_.value();
    return false;
  }
  instr_checksum_ = pe_file.nt_headers()->OptionalHeader.CheckSum;
  instr_size_ = pe_file.nt_headers()->OptionalHeader.SizeOfImage;
  instr_time_date_stamp_ = pe_file.nt_headers()->FileHeader.TimeDateStamp;
  return true;
}

bool Reorderer::MatchesInstrumentedModuleSignature(
    const ModuleInformation& module_info) const {
  return (instr_checksum_ == module_info.image_checksum &&
      instr_size_ == module_info.module_size &&
      instr_time_date_stamp_ == module_info.time_date_stamp);
}

// KernelModuleEvents implementation.
void Reorderer::OnModuleIsLoaded(DWORD process_id,
                                 const base::Time& time,
                                 const ModuleInformation& module_info) {
  // Simply forward this to OnModuleLoad.
  OnModuleLoad(process_id, time, module_info);
}

void Reorderer::OnModuleUnload(DWORD process_id,
                               const base::Time& time,
                               const ModuleInformation& module_info) {
  // Avoid doing needless work.
  if (consumer_errored_ || module_info.module_size == 0)
    return;

  if (last_event_time_ > time) {
    LOG(ERROR) << "Messages out of temporal order.";
    consumer_errored_ = true;
    return;
  }

  ModuleSpace& module_space = processes_[process_id];
  AbsoluteAddress64 addr(module_info.base_address);
  ModuleSpace::Range range(addr, module_info.module_size);
  ModuleSpace::RangeMapIter it =
      module_space.FindFirstIntersection(range);
  if (it == module_space.end()) {
    // We occasionally see this, as certain modules fire off multiple Unload
    // events, so we don't log an error. I'm looking at you, logman.exe.
    return;
  }
  if (!(it->first == range)) {
    LOG(ERROR) << "Trying to remove module with mismatching range: "
               << module_info.image_file_name;
    consumer_errored_ = true;
    return;
  }

  module_space.Remove(it);
  last_event_time_ = time;
}

void Reorderer::OnModuleLoad(DWORD process_id,
                             const base::Time& time,
                             const ModuleInformation& module_info) {
  // Avoid doing needless work.
  if (consumer_errored_ || module_info.module_size == 0)
    return;

  if (last_event_time_ > time) {
    LOG(ERROR) << "Messages out of temporal order.";
    consumer_errored_ = true;
    return;
  }

  ModuleSpace& module_space = processes_[process_id];
  AbsoluteAddress64 addr(module_info.base_address);
  ModuleSpace::Range range(addr, module_info.module_size);
  if (!module_space.Insert(range, module_info)) {
    ModuleSpace::RangeMapIter it = module_space.FindFirstIntersection(range);
    DCHECK(it != module_space.end());
    LOG(ERROR) << "Trying to insert conflicting module: "
               << module_info.image_file_name;
    consumer_errored_ = true;
    return;
  }

  last_event_time_ = time;
}

// CallTraceEvents implementation.
void Reorderer::OnTraceEntry(base::Time time,
                             DWORD process_id,
                             DWORD thread_id,
                             const TraceEnterExitEventData* data) {
  // We currently don't care about TraceEntry events.
}

void Reorderer::OnTraceExit(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const TraceEnterExitEventData* data) {
  // We currently don't care about TraceExit events.
}

void Reorderer::OnTraceBatchEnter(base::Time time,
                                  DWORD process_id,
                                  DWORD thread_id,
                                  const TraceBatchEnterData* data) {
  // Avoid doing needless work.
  if (consumer_errored_)
    return;

  for (size_t i = 0; i < data->num_calls; ++i) {
    AbsoluteAddress64 function_address =
        reinterpret_cast<AbsoluteAddress64>(data->calls[i].function);
    const ModuleInformation* module_info =
        GetModuleInformation(process_id, function_address);

    // Don't parse this event unless it belongs to the instrumented module
    // of interest.
    if (module_info == NULL ||
        !MatchesInstrumentedModuleSignature(*module_info))
      continue;

    // Get the block that this function call refers to. We can only instrument
    // 32-bit DLLs, so we're sure that the following address conversion is safe.
    RelativeAddress rva(
        static_cast<uint32>(function_address - module_info->base_address));
    const BlockGraph::Block* block =
        image_->address_space.GetBlockByAddress(rva);
    if (block == NULL) {
      LOG(ERROR) << "Unable to map relative address "
                 << base::StringPrintf("0x%08d", rva.value())
                 << " to a block.";
      consumer_errored_ = true;
      return;
    }
    if (block->type() != BlockGraph::CODE_BLOCK) {
      LOG(ERROR) << "Address " << base::StringPrintf("0x%08d", rva.value())
                 << " maps to a non-code block.";
      consumer_errored_ = true;
      return;
    }

    // Get the actual time of the call. We ignore ticks_ago for now, as the
    // low-resolution and rounding can cause inaccurate relative timings. We
    // simply rely on the buffer ordering (via UniqueTime's internal counter)
    // to maintain relative ordering. For future reference, ticks_ago are in
    // milliseconds, according to MSDN.
    UniqueTime entry_time(time);

    ++code_block_entry_events_;
    if (!order_generator_->OnCodeBlockEntry(*this, block, rva, process_id,
                                            thread_id, entry_time)) {
      consumer_errored_ = true;
      return;
    }
  }
}

void Reorderer::OnEvent(PEVENT_TRACE event) {
  if (!call_trace_parser_.ProcessOneEvent(event))
    kernel_log_parser_.ProcessOneEvent(event);
}

void Reorderer::ProcessEvent(PEVENT_TRACE event) {
  DCHECK(consumer_ != NULL);
  consumer_->OnEvent(event);
}

bool Reorderer::ProcessBuffer(PEVENT_TRACE_LOGFILE buffer) {
  DCHECK(consumer_ != NULL);
  // If our consumer is errored, we bail early.
  if (consumer_->consumer_errored_)
    return false;
  return true;
}

const sym_util::ModuleInformation* Reorderer::GetModuleInformation(
    uint32 process_id, AbsoluteAddress64 addr) const {
  ProcessMap::const_iterator processes_it = processes_.find(process_id);
  if (processes_it == processes_.end())
    return NULL;

  const ModuleSpace& module_space(processes_it->second);
  ModuleSpace::Range range(addr, 1);
  ModuleSpace::RangeMapConstIter module_it =
      module_space.FindFirstIntersection(range);
  if (module_it == module_space.end())
    return NULL;

  return &module_it->second;
}

bool Reorderer::Order::SerializeToJSON(const FilePath &path,
                                       bool pretty_print) const {
  file_util::ScopedFILE file(file_util::OpenFile(path, "wb"));
  if (file.get() == NULL)
    return false;
  return SerializeToJSON(file.get(), pretty_print);
}

bool Reorderer::Order::SerializeToJSON(FILE* file,
                                       bool pretty_print) const {
  if (fprintf(file, "// %s\n", comment.c_str()) == EOF)
    return false;
  if (fputc('[', file) == EOF)
    return false;
  if (pretty_print && fputc('\n', file) == EOF)
    return false;

  // Output the individual block lists.
  BlockListMap::const_iterator it = section_block_lists.begin();
  int lists_output = 0;
  for (; it != section_block_lists.end(); ++it) {
    if (it->second.size() == 0)
      continue;

    if (lists_output > 0) {
      if (fputc(',', file) == EOF)
        return false;
      if (pretty_print && fputc('\n', file) == EOF)
        return false;
    }

    if (!OutputBlockList(file, it->first, it->second, 2, pretty_print))
      return false;

    ++lists_output;
  }

  if (lists_output > 0 && pretty_print && fputc('\n', file) == EOF)
    return false;
  if (fputc(']', file) == EOF)
    return false;
  if (pretty_print && fputc('\n', file) == EOF)
    return false;

  return true;
}

bool Reorderer::Order::LoadFromJSON(const FilePath& path) {
  std::string file_string;
  if (!file_util::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string";
    return false;
  }

  scoped_ptr<Value> value(base::JSONReader::Read(file_string, false));
  ListValue* order = NULL;
  if (value.get() == NULL || !value->GetAsList(&order)) {
    LOG(ERROR) << "Order file does not contain a valid JSON list.";
    return false;
  }

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
          image.address_space.GetBlockByAddress(rva);
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

bool Reorderer::Order::OutputFaultEstimates(const FilePath& path) const {
  file_util::ScopedFILE file(file_util::OpenFile(path, "wb"));
  if (file.get() == NULL)
    return false;
  return OutputFaultEstimates(file.get());
}

bool Reorderer::Order::OutputFaultEstimates(FILE* file) const {
  DCHECK(file != NULL);

  const BlockGraph::BlockType kTypes[] = {
      BlockGraph::CODE_BLOCK, BlockGraph::DATA_BLOCK };
  const char* kTypeNames[] = { "code", "data" };

  // Stores page sizes per block type.
  size_t kDefaultPageSize = 16 * 1024;
  std::map<BlockGraph::BlockType, size_t> page_sizes;
  page_sizes[BlockGraph::CODE_BLOCK] = 32 * 1024;
  page_sizes[BlockGraph::DATA_BLOCK] = 16 * 1024;

  // Iterate over each section, and output statistics.
  size_t pre_total = 0, post_total = 0;
  BlockListMap::const_iterator it = section_block_lists.begin();
  for (; it != section_block_lists.end(); ++it) {
    size_t section_id = it->first;
    const BlockList& blocks = it->second;

    if (blocks.size() == 0)
      continue;

    // Get section type and page size.
    BlockGraph::BlockType section_type = blocks[0]->type();
    size_t page_size = page_sizes[section_type];
    if (page_size == 0)
      page_size = kDefaultPageSize;

    // This stores the list of page ids that would need to be loaded for
    // this section prior to reordering (using original addresses).
    std::set<size_t> pre_page_set;

    // Translate each block call into a page id, and keep track of which pages
    // need to be loaded (both before and after reordering).
    size_t post_address = 0;
    for (size_t i = 0; i < blocks.size(); ++i) {
      const BlockGraph::Block* block = blocks[i];
      BlockGraph::BlockType type = block->type();

      // Get the pre and post addresses of this block.
      size_t pre_address = block->addr().value();
      post_address += block->size();

      // Turn this range into a page start and page end. This is necessary
      // if a block crosses a page boundary.
      size_t pre_page_start = pre_address / page_size;
      size_t pre_page_end = (pre_address + block->size() - 1) / page_size;

      // Mark the pages as needing to be read.
      for (size_t i = pre_page_start; i <= pre_page_end; ++i)
        pre_page_set.insert(i);
    }

    // Output the estimated faults.
    size_t pre_count = pre_page_set.size();
    size_t post_count = (post_address + page_size - 1) / page_size;
    pre_total += pre_count;
    post_total += post_count;
    fprintf(file,
            "section %d (%s): pre = %8d, post = %8d, reduction = %6.1f%%\n",
            section_id, kTypeNames[section_type], pre_count, post_count,
            (pre_count - post_count) * 100.0 / pre_count);
  }

  // Output summary statistics.
  fprintf(file,
          // "section x (yyyy): "
             "total           : pre = %8d, post = %8d, reduction = %6.1f%%\n",
          pre_total, post_total,
          (pre_total - post_total) * 100.0 / pre_total);

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
