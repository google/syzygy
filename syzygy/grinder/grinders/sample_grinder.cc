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

#include "syzygy/grinder/grinders/sample_grinder.h"

#include "base/string_util.h"
#include "syzygy/common/align.h"
#include "syzygy/grinder/basic_block_util.h"

namespace grinder {
namespace grinders {

namespace {

using basic_block_util::ModuleInformation;
using trace::parser::AbsoluteAddress64;

core::RelativeAddress GetBucketStart(const TraceSampleData* sample_data) {
  DCHECK(sample_data != NULL);
  return core::RelativeAddress(
      reinterpret_cast<uint32>(sample_data->bucket_start) -
          reinterpret_cast<uint32>(sample_data->module_base_addr));
}

}  // namespace

const char SampleGrinder::kAggregationLevel[] = "aggregation-level";

SampleGrinder::SampleGrinder()
    : aggregation_level_(kBasicBlock),
      parser_(NULL),
      event_handler_errored_(false),
      clock_rate_(0.0) {
}

SampleGrinder::~SampleGrinder() {
}

bool SampleGrinder::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  if (command_line->HasSwitch(kAggregationLevel)) {
    std::string s = command_line->GetSwitchValueASCII(kAggregationLevel);
    if (LowerCaseEqualsASCII(s, "basic-block")) {
      aggregation_level_ = kBasicBlock;
    } else if (LowerCaseEqualsASCII(s, "function")) {
      aggregation_level_ = kFunction;
    } else if (LowerCaseEqualsASCII(s, "compiland")) {
      aggregation_level_ = kCompiland;
    } else {
      LOG(ERROR) << "Unknown aggregation level: " << s << ".";
      return false;
    }
  }

  return true;
}

void SampleGrinder::SetParser(Parser* parser) {
  DCHECK(parser != NULL);
  parser_ = parser;
}

bool SampleGrinder::Grind() {
  if (event_handler_errored_) {
    LOG(WARNING) << "Failed to handle all TraceSampleData records, results "
                 << "will be partial.";
  }

  // TODO(chrisha): Implement rolling up.
  LOG(WARNING) << "Grind not implemented.";
  return true;
}

bool SampleGrinder::OutputData(FILE* file) {
  // TODO(chrisha): Implement output.
  LOG(WARNING) << "OutputData not implemented.";
  return true;
}

void SampleGrinder::OnProcessStarted(base::Time time,
                                     DWORD process_id,
                                     const TraceSystemInfo* data) {
  DCHECK(data != NULL);
  clock_rate_ = data->clock_info.tsc_info.frequency;
  return;
}

// @name ParseEventHandler implementation.
// @{
// Override of the OnSampleData callback.
void SampleGrinder::OnSampleData(base::Time Time,
                                 DWORD process_id,
                                 const TraceSampleData* data) {
  DCHECK(data != NULL);

  if (data->bucket_count == 0) {
    LOG(INFO) << "Skipping empty TraceSampleData record.";
    return;
  }

  const ModuleInformation* module_info = parser_->GetModuleInformation(
      process_id, AbsoluteAddress64(data->module_base_addr));
  if (module_info == NULL) {
    LOG(ERROR) << "Failed to find module information for TraceSampleData "
               << "record.";
    event_handler_errored_ = true;
    return;
  }

  // Get the summary data associated with this module.
  ModuleData* module_data = GetModuleData(
      base::FilePath(module_info->image_file_name), data);

  // Make sure that we have a high enough bucket resolution to be able to
  // represent the data that we're processing. This may involve 'upsampling'
  // previously collected data.
  UpsampleModuleData(data, module_data);

  // Update our running totals.
  IncrementModuleData(clock_rate_, data, module_data);

  return;
}

SampleGrinder::ModuleData* SampleGrinder::GetModuleData(
    const base::FilePath& module_path,
    const TraceSampleData* sample_data) {
  DCHECK(sample_data != NULL);

  // Fill out the key portion of the ModuleSampleData and find/insert a new
  // entry into the set.
  ModuleKey key = { sample_data->module_size,
                    sample_data->module_checksum,
                    sample_data->module_time_date_stamp };

  // Find or insert the module data.
  std::pair<ModuleDataMap::iterator, bool> result = module_data_.insert(
        std::make_pair(key, ModuleData()));

  // If this was a fresh insertion then set the path.
  if (result.second)
    result.first->second.module_path = module_path;

  DCHECK(result.first != module_data_.end());
  return &(result.first->second);
}

void SampleGrinder::UpsampleModuleData(
    const TraceSampleData* sample_data,
    SampleGrinder::ModuleData* module_data) {
  DCHECK(sample_data != NULL);
  DCHECK(module_data != NULL);

  // Special case: we're not yet initialized. Simply allocate buckets.
  if (module_data->bucket_size == 0) {
    module_data->bucket_size = sample_data->bucket_size;
    module_data->bucket_start = GetBucketStart(sample_data);
    module_data->buckets.resize(sample_data->bucket_count);
    return;
  }

  // If we're already as coarse or finer then there's nothing to do.
  if (module_data->bucket_size <= sample_data->bucket_size)
    return;

  // Grow the buckets in place, and then fill in the scaled values tail first.
  std::vector<double>& buckets = module_data->buckets;
  size_t old_size = buckets.size();
  size_t factor = module_data->bucket_size / sample_data->bucket_size;
  size_t new_size = old_size * factor;
  buckets.resize(new_size);
  for (size_t i = old_size, j = new_size; i > 0; ) {
    --i;
    double new_value = buckets[i] / factor;

    for (size_t k = 0; k < factor; ++k) {
      --j;
      buckets[j] = new_value;
    }
  }

  // Update the bucket size.
  module_data->bucket_size = sample_data->bucket_size;

  return;
}

// Increments the module data with the given sample data. Returns false and
// logs if this is not possible due to invalid data.
bool SampleGrinder::IncrementModuleData(
    double clock_rate,
    const TraceSampleData* sample_data,
    SampleGrinder::ModuleData* module_data) {
  DCHECK_LT(0.0, clock_rate);
  DCHECK(sample_data != NULL);
  DCHECK(module_data != NULL);
  DCHECK(common::IsPowerOfTwo(sample_data->bucket_size));
  DCHECK(common::IsPowerOfTwo(module_data->bucket_size));
  DCHECK_GE(sample_data->bucket_size, module_data->bucket_size);

  // The bucket starts need to be consistent.
  if (GetBucketStart(sample_data) != module_data->bucket_start) {
    LOG(ERROR) << "TraceSampleData has an inconsistent bucket start.";
    return false;
  }

  // Calculate how many aggregate buckets are touched per sample bucket.
  size_t factor = sample_data->bucket_size / module_data->bucket_size;

  // The number of buckets also need to be consistent. The bucket size in
  // the sample data is strictly greater than ours. If we convert to the number
  // of equivalent buckets there should be no more than factor - 1 more of them
  // in order for the module sizes to be consistent.
  size_t equivalent_buckets = sample_data->bucket_size *
      sample_data->bucket_count / module_data->bucket_size;
  DCHECK_GE(equivalent_buckets, module_data->buckets.size());
  if (equivalent_buckets - module_data->buckets.size() >= factor) {
    LOG(ERROR) << "TraceSampleData has inconsistent bucket count.";
    return false;
  }

  // Calculate the scaling factor which will convert a sample into 'seconds'
  // spent in that sample.
  double seconds = static_cast<double>(sample_data->sampling_interval) /
      clock_rate;

  // Walk through the sample buckets.
  const uint32* buckets = sample_data->buckets;
  std::vector<double>& agg_buckets = module_data->buckets;
  for (size_t i = 0, j = 0; i < sample_data->bucket_count; ++i) {
    // Special case: handle empty buckets explicitly, as they often occur.
    if (buckets[i] == 0) {
      j += factor;
      continue;
    }

    // Scale the sample count so that it represents 'seconds' spent in the
    // given block.
    double weight = static_cast<double>(buckets[i]) * seconds / factor;

    // Walk through the touched aggregate buckets and increment them.
    for (size_t k = 0; k < factor; ++k, ++j)
      agg_buckets[j] += weight;
  }

  return true;
}

bool SampleGrinder::ModuleKey::operator<(
    const ModuleKey& rhs) const {
  if (module_size < rhs.module_size)
    return true;
  if (module_size > rhs.module_size)
    return false;
  if (module_checksum < rhs.module_checksum)
    return true;
  if (module_checksum > rhs.module_checksum)
    return false;
  if (module_time_date_stamp < rhs.module_time_date_stamp)
    return true;
  return false;
}

}  // namespace grinders
}  // namespace grinder
