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

#include "syzygy/refinery/analyzers/memory_analyzer.h"

#include <dbghelp.h>
#include <string>

#include "base/memory/scoped_ptr.h"

namespace refinery {

Analyzer::AnalysisResult MemoryAnalyzer::Analyze(
    const Minidump& minidump, ProcessState* process_state) {
  DCHECK(process_state != nullptr);

  scoped_refptr<ProcessState::Layer<Bytes>> bytes_layer;
  process_state->FindOrCreateLayer(&bytes_layer);

  Minidump::Stream memory_list =
      minidump.FindNextStream(nullptr, MemoryListStream);
  if (!memory_list.IsValid())
    return ANALYSIS_ERROR;
  // Ensure MemoryListStream is unique.
  Minidump::Stream offending_list =
      minidump.FindNextStream(&memory_list, MemoryListStream);
  if (offending_list.IsValid())
    return ANALYSIS_ERROR;

  ULONG32 num_ranges = 0;
  if (!memory_list.ReadElement(&num_ranges))
    return ANALYSIS_ERROR;

  for (size_t i = 0; i < num_ranges; ++i) {
    MINIDUMP_MEMORY_DESCRIPTOR descriptor = {};
    if (!memory_list.ReadElement(&descriptor))
      return ANALYSIS_ERROR;

    Address range_addr = descriptor.StartOfMemoryRange;
    Size range_size = descriptor.Memory.DataSize;
    Minidump::Stream bytes_stream = minidump.GetStreamFor(descriptor.Memory);

    std::string bytes;
    if (!bytes_stream.ReadBytes(range_size, &bytes))
      return ANALYSIS_ERROR;

    AddressRange range(range_addr, range_size);
    if (!range.IsValid())
      return ANALYSIS_ERROR;

    // Create the memory record.
    scoped_refptr<ProcessState::Record<Bytes>> bytes_record;
    bytes_layer->CreateRecord(range, &bytes_record);
    Bytes* bytes_proto = bytes_record->mutable_data();
    bytes_proto->mutable_data()->swap(bytes);
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
