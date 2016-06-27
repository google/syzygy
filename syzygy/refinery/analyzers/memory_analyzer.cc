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
#include <memory>
#include <string>

#include "syzygy/core/address_space.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

namespace {

using MemoryAddressSpace = core::AddressSpace<Address, Size, std::string>;

bool RecordMemoryContents(AddressRange new_range,
                          std::string bytes,
                          MemoryAddressSpace* address_space) {
  DCHECK(address_space);
  DCHECK_EQ(new_range.size(), bytes.size());

  MemoryAddressSpace::iterator it =
      address_space->FindFirstIntersection(new_range);
  for (; it != address_space->end() && it->first.Intersects(new_range); ++it) {
    const auto& range = it->first;
    const std::string& data = it->second;
    // If this range is fully subsumed by the new range there's nothing
    // to do. Otherwise we need to slice the data and prepend and/or append
    // it to the new range and data.
    if (range.start() < new_range.start()) {
      size_t prepend = new_range.start() - range.start();
      bytes.insert(0, data, 0, prepend);
      new_range = AddressRange(range.start(), new_range.size() + prepend);
    }
    if (range.end() > new_range.end()) {
      size_t append = range.end() - new_range.end();
      bytes.append(data, data.size() - append, append);
      new_range = AddressRange(new_range.start(), new_range.size() + append);
    }
  }
  DCHECK_EQ(new_range.size(), bytes.size());

  if (!address_space->SubsumeInsert(new_range, bytes)) {
    NOTREACHED() << "SubsumeInsert failed!";
    return false;
  }

  return true;
}

}  // namespace

// static
const char MemoryAnalyzer::kMemoryAnalyzerName[] = "MemoryAnalyzer";

Analyzer::AnalysisResult MemoryAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);

  BytesLayerPtr bytes_layer;
  process_analysis.process_state()->FindOrCreateLayer(&bytes_layer);

  // It seems minidumps sometimes contain overlapping memory ranges. It's
  // difficult to reason on why this is, and it's difficult to know which byte
  // value of two or more alternates is "the one". To consolidate this
  // consistently into the byte layer we choose the byte values from the last
  // range that supplies a given byte.
  using MemoryAddressSpace = core::AddressSpace<Address, Size, std::string>;
  MemoryAddressSpace memory_temp;
  minidump::Minidump::TypedMemoryList memory_list = minidump.GetMemoryList();
  if (!memory_list.IsValid())
      return ANALYSIS_ERROR;

  for (const auto& descriptor : memory_list) {
    Address range_addr = descriptor.StartOfMemoryRange;
    Size range_size = descriptor.Memory.DataSize;

    // It seems minidumps can contain zero sized memory ranges.
    if (range_size == 0U)
      continue;

    minidump::Minidump::Stream bytes_stream =
        minidump.GetStreamFor(descriptor.Memory);

    std::string bytes;
    if (!bytes_stream.ReadAndAdvanceBytes(range_size, &bytes))
      return ANALYSIS_ERROR;

    AddressRange new_range(range_addr, range_size);
    if (!new_range.IsValid())
      return ANALYSIS_ERROR;

    // Record the new range and consolidate it with any overlaps.
    if (!RecordMemoryContents(new_range, bytes, &memory_temp))
      return ANALYSIS_ERROR;
  }

  // Now transfer the temp address space to the bytes layer.
  for (const auto& entry : memory_temp) {
    // Create the memory record.
    AddressRange new_range(entry.first.start(), entry.first.size());
    BytesRecordPtr bytes_record;
    bytes_layer->CreateRecord(new_range, &bytes_record);
    Bytes* bytes_proto = bytes_record->mutable_data();
    bytes_proto->mutable_data()->assign(entry.second);
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
