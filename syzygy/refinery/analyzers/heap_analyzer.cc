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

#include "syzygy/refinery/analyzers/heap_analyzer.h"

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/refinery/detectors/lfh_entry_detector.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

namespace {

scoped_refptr<TypeRepository> GetNtdllTypes(ProcessState* process_state,
                                            SymbolProvider* symbol_provider) {
  ModuleLayerPtr modules;
  if (!process_state->FindLayer(&modules)) {
    LOG(ERROR) << "No modules layer.";
    return nullptr;
  }

  for (const auto& module_sig : modules->data().signatures()) {
    if (base::EndsWith(module_sig.path, L"ntdll.dll",
                       base::CompareCase::INSENSITIVE_ASCII)) {
      pe::PEFile::Signature signature(
          module_sig.path, core::AbsoluteAddress(0U), module_sig.module_size,
          module_sig.module_checksum, module_sig.module_time_date_stamp);
      scoped_refptr<TypeRepository> ret;

      if (symbol_provider->FindOrCreateTypeRepository(signature, &ret))
        return ret;
    }
  }

  return nullptr;
}

bool RecordFoundRun(const LFHEntryDetector::LFHEntryRun& run,
                    UserDefinedTypePtr entry_type,
                    ProcessState* process_state) {
  HeapMetadataLayerPtr meta_layer;
  process_state->FindOrCreateLayer(&meta_layer);
  HeapAllocationLayerPtr alloc_layer;
  process_state->FindOrCreateLayer(&alloc_layer);

  for (Address entry_address = run.first_entry; entry_address <= run.last_entry;
       entry_address += run.entry_distance_bytes) {
    // Check the state of the entry for the metadata and to record the state
    // and size of the allocation.
    TypedData entry(process_state, entry_type, entry_address);
    TypedData extended_block_signature_field;
    if (!entry.GetNamedField(L"ExtendedBlockSignature",
                             &extended_block_signature_field)) {
      // If the field is missing from the type, that's an error.
      return false;
    }

    const uint16_t kLFHBlockFlag = 0x80;
    uint64_t extended_block_signature = 0;
    DCHECK_LT(entry_type->size(), run.entry_distance_bytes);
    size_t allocation_size = run.entry_distance_bytes - entry_type->size();
    bool entry_is_corrupt = false;
    uint64_t decoded_subsegment = 0;
    if (!LFHEntryDetector::GetDecodedLFHEntrySubsegment(entry,
                                                        &decoded_subsegment)) {
      // This really shouldn't happen.
      NOTREACHED() << "Unable to get decoded LFH subsegment.";
      return false;
    }
    if (decoded_subsegment != run.subsegment_code) {
      // If the subsegment code doesn't match, the entry is corrupt.
      entry_is_corrupt = true;
    }

    bool alloc_is_free = true;
    if (!extended_block_signature_field.GetUnsignedValue(
            &extended_block_signature) ||
        (extended_block_signature & kLFHBlockFlag) == 0) {
      // If we can't retrieve the value, or the high bit is clear, we assume
      // a corrupt entry.
      entry_is_corrupt = true;
      DCHECK_EQ(true, alloc_is_free);
    } else {
      // Mask off the flag bit, the remainder should be unused bytes + 8 or
      // zero - zero marking an unused (free) block.
      extended_block_signature &= ~kLFHBlockFlag;
      if (extended_block_signature == 0) {
        // It's a free block, no header corruption that we can determine.
        DCHECK_EQ(true, alloc_is_free);
      } else if (extended_block_signature < 8) {
        // The header is corrupt.
        entry_is_corrupt = true;
      } else {
        size_t unused_bytes = extended_block_signature - 8;
        if (unused_bytes >= allocation_size) {
          // This is un-possible, must be corruption.
          entry_is_corrupt = true;
          DCHECK_EQ(true, alloc_is_free);
        } else {
          // Unused bytes is reasonable, record this as a used block.
          allocation_size -= unused_bytes;
          alloc_is_free = false;
        }
      }
    }

    // Create the record for the entry's metadata.
    AddressRange entry_range(entry_address, entry_type->size());
    HeapMetadataRecordPtr meta_record;
    meta_layer->CreateRecord(entry_range, &meta_record);
    HeapMetadata* meta_data = meta_record->mutable_data();
    meta_data->set_corrupt(entry_is_corrupt);

    // Record the allocation itself.
    AddressRange alloc_range(entry_range.end(), allocation_size);
    HeapAllocationRecordPtr alloc_record;
    alloc_layer->CreateRecord(alloc_range, &alloc_record);
    HeapAllocation* allocation = alloc_record->mutable_data();
    allocation->set_is_free(alloc_is_free);
  }

  return true;
}

bool RecordFoundRuns(const LFHEntryDetector::LFHEntryRuns& found_runs,
                     UserDefinedTypePtr entry_type,
                     ProcessState* process_state) {
  DCHECK_NE(0U, found_runs.size());

  for (const auto& run : found_runs) {
    // For now, simply record all runs of three or more entries. A run of two
    // likely means that we've scored on the birthday paradox.
    // TODO(siggi): Improve on this.
    // One possibility is to build the max likelyhood view, where something to
    // watch out for is the elimination of strong findings that are extended at
    // either end by a false positive match. Adding LFH userdata header
    // detection
    // into the mix will add another degree of matching to this.
    if (run.entries_found > 2 &&
        !RecordFoundRun(run, entry_type, process_state))
      return false;
  }

  return true;
}

}  // namespace

// static
const char HeapAnalyzer::kHeapAnalyzerName[] = "HeapAnalyzer";

HeapAnalyzer::HeapAnalyzer() {
}

Analyzer::AnalysisResult HeapAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);
  DCHECK(process_analysis.symbol_provider() != nullptr);

  // TODO(siggi): At present this won't work for XP, figure out how to reject
  //     XP dumps?
  // Start by finding the NTDLL module record and symbols, as that's where we
  // come by the symbols that describe the heap.
  scoped_refptr<TypeRepository> ntdll_repo =
      GetNtdllTypes(process_analysis.process_state(),
                    process_analysis.symbol_provider().get());
  if (!ntdll_repo) {
    LOG(ERROR) << "Couldn't get types for NTDLL.";
    return ANALYSIS_ERROR;
  }

  LFHEntryDetector detector;
  if (!detector.Init(ntdll_repo.get(), process_analysis.process_state())) {
    LOG(ERROR) << "Failed to initialize LFH detector.";
    return ANALYSIS_ERROR;
  }

  BytesLayerPtr bytes_layer;
  if (!process_analysis.process_state()->FindLayer(&bytes_layer)) {
    LOG(ERROR) << "Failed to find bytes layer.";
    return ANALYSIS_ERROR;
  }

  // Perform detection on the records from the bytes layer.
  for (const auto& record : *bytes_layer) {
    // TODO(siggi): Skip stacks, and perhaps modules here.
    LFHEntryDetector::LFHEntryRuns found_runs;
    if (!detector.Detect(record->range(), &found_runs)) {
      LOG(ERROR) << "Detection failed.";
      return ANALYSIS_ERROR;
    }

    if (found_runs.size()) {
      if (!RecordFoundRuns(found_runs, detector.entry_type(),
                           process_analysis.process_state())) {
        LOG(ERROR) << "Failed to record found runs.";
        // TODO(siggi): Is this the right thing to do?
        return ANALYSIS_ERROR;
      }
    }
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
