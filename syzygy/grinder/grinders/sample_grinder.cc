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

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/align.h"
#include "syzygy/grinder/cache_grind_writer.h"
#include "syzygy/grinder/coverage_data.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace grinder {
namespace grinders {

namespace {

using basic_block_util::ModuleInformation;
using trace::parser::AbsoluteAddress64;

typedef block_graph::BlockGraph BlockGraph;
typedef core::AddressRange<core::RelativeAddress, size_t> Range;
typedef SampleGrinder::HeatMap HeatMap;

core::RelativeAddress GetBucketStart(const TraceSampleData* sample_data) {
  DCHECK(sample_data != NULL);
  return core::RelativeAddress(
      reinterpret_cast<uint32>(sample_data->bucket_start) -
          reinterpret_cast<uint32>(sample_data->module_base_addr));
}

// Returns the size of an intersection between a given address range and a
// sample bucket.
size_t IntersectionSize(const Range& range,
                        const core::RelativeAddress& bucket_start,
                        size_t bucket_size) {
  size_t left = std::max(range.start().value(), bucket_start.value());
  size_t right = std::min(range.end().value(),
                          bucket_start.value() + bucket_size);
  if (right <= left)
    return 0;
  return right - left;
}

bool BuildHeatMapForCodeBlock(const pe::PETransformPolicy& policy,
                              const Range& block_range,
                              const BlockGraph::Block* block,
                              core::StringTable* string_table,
                              HeatMap* heat_map) {
  DCHECK(block != NULL);
  DCHECK(string_table != NULL);
  DCHECK(heat_map != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  const std::string* compiland = &string_table->InternString(
      block->compiland_name());
  const std::string* function = &string_table->InternString(
      block->name());
  SampleGrinder::BasicBlockData data = { compiland, function, 0.0 };

  // If the code block is basic block decomposable then decompose it and
  // iterate over its basic blocks.
  bool handled_basic_blocks = false;
  if (policy.BlockIsSafeToBasicBlockDecompose(block)) {
    block_graph::BasicBlockSubGraph bbsg;
    block_graph::BasicBlockDecomposer bbd(block, &bbsg);
    if (bbd.Decompose()) {
      block_graph::BasicBlockSubGraph::BBCollection::const_iterator bb_it =
          bbsg.basic_blocks().begin();
      for (; bb_it != bbsg.basic_blocks().end(); ++bb_it) {
        const block_graph::BasicBlock* bb = *bb_it;
        DCHECK(bb != NULL);

        if (bb->type() != block_graph::BasicBlock::BASIC_CODE_BLOCK)
          continue;
        const block_graph::BasicCodeBlock* bcb =
            block_graph::BasicCodeBlock::Cast(bb);
        DCHECK(bcb != NULL);

        block_graph::BasicBlockSubGraph::Offset offset = bcb->offset();
        DCHECK_NE(block_graph::BasicBlock::kNoOffset, offset);
        core::RelativeAddress rva(block_range.start() + offset);

        // Add a range for the basic-block if it has non-zero size.
        if (bcb->GetInstructionSize() != 0) {
          Range range(rva, bcb->GetInstructionSize());
          if (!heat_map->Insert(range, data)) {
            LOG(ERROR) << "Failed to insert basic code block into heat map.";
            return false;
          }
        }

        // Iterate over any successors.
        if (!bcb->successors().empty()) {
          // The instruction that the successor represents immediately follows
          // the instruction itself.
          rva += bcb->GetInstructionSize();

          block_graph::BasicBlock::Successors::const_iterator succ_it =
              bcb->successors().begin();
          for (; succ_it != bcb->successors().end(); ++succ_it) {
            if (succ_it->instruction_size() != 0) {
              Range range(rva, succ_it->instruction_size());
              if (!heat_map->Insert(range, data)) {
                LOG(ERROR) << "Failed to insert successor into heat map.";
                return false;
              }
            }
          }
        }
      }
      handled_basic_blocks = true;
    }
  }

  if (!handled_basic_blocks) {
    // If we couldn't basic block decompose then we simply treat it as a
    // single macro block.
    if (!heat_map->Insert(block_range, data)) {
      LOG(ERROR) << "Failed to insert code block into heat map.";
      return false;
    }
  }

  return true;
}

// Builds an empty heat map for the given module. One range is created per
// basic-block. Non-decomposable code blocks are represented by a single range.
bool BuildEmptyHeatMap(const SampleGrinder::ModuleKey& module_key,
                       const SampleGrinder::ModuleData& module_data,
                       core::StringTable* string_table,
                       HeatMap* heat_map) {
  DCHECK(string_table != NULL);
  DCHECK(heat_map != NULL);

  pe::PEFile image;
  if (!image.Init(module_data.module_path)) {
    LOG(ERROR) << "Failed to read PE file \""
               << module_data.module_path.value() << "\".";
    return false;
  }

  // Decompose the module.
  pe::Decomposer decomposer(image);
  BlockGraph bg;
  pe::ImageLayout image_layout(&bg);
  LOG(INFO) << "Decomposing module \"" << module_data.module_path.value()
            << "\".";
  if (!decomposer.Decompose(&image_layout)) {
    LOG(ERROR) << "Failed to decompose module \""
               << module_data.module_path.value() << "\".";
    return false;
  }

  pe::PETransformPolicy policy;

  // Iterate over all of the code blocks and basic-block decompose them.
  LOG(INFO) << "Creating initial basic-block heat map for module \""
            << module_data.module_path.value() << "\".";
  BlockGraph::AddressSpace::AddressSpaceImpl::const_iterator block_it =
      image_layout.blocks.begin();
  for (; block_it != image_layout.blocks.end(); ++block_it) {
    // We only care about code blocks. We also don't care about gap blocks,
    // which have no meaningful content.
    const BlockGraph::Block* block = block_it->second;
    if (block->type() != BlockGraph::CODE_BLOCK)
      continue;
    if (block->attributes() & BlockGraph::GAP_BLOCK)
      continue;

    if (!BuildHeatMapForCodeBlock(policy, block_it->first, block, string_table,
                                  heat_map)) {
      return false;
    }
  }

  return true;
}

bool BuildEmptyHeatMap(const base::FilePath& image_path,
                       LineInfo* line_info,
                       HeatMap* heat_map) {
  DCHECK(line_info != NULL);
  DCHECK(heat_map != NULL);

  base::FilePath pdb_path;
  if (!pe::FindPdbForModule(image_path, &pdb_path) ||
      pdb_path.empty()) {
    LOG(ERROR) << "Unable to find PDB for image \"" << image_path.value()
               << "\".";
    return false;
  }
  if (!line_info->Init(pdb_path)) {
    LOG(ERROR) << "Failed to read line info from PDB \""
               << pdb_path.value() << "\".";
    return false;
  }

  for (size_t i = 0; i < line_info->source_lines().size(); ++i) {
    const LineInfo::SourceLine& line = line_info->source_lines()[i];
    SampleGrinder::BasicBlockData data = { NULL, NULL, 0.0 };
    Range range(line.address, line.size);
    // We don't care about collisions, because there are often multiple
    // lines that will map to the same source range.
    heat_map->Insert(range, data);
  }

  return true;
}

bool RollUpToLines(const HeatMap& heat_map, LineInfo* line_info) {
  DCHECK(line_info != NULL);

  // Determine the minimum non-zero amount of heat in any bucket. We scale
  // heat by this to integer values.
  double min_heat = std::numeric_limits<double>::max();
  HeatMap::const_iterator heat_it = heat_map.begin();
  for (; heat_it != heat_map.end(); ++heat_it) {
    double h = heat_it->second.heat;
    if (h > 0 && h < min_heat)
      min_heat = h;
  }

  // Scale the heat values to integers, and update the line info.
  for (heat_it = heat_map.begin(); heat_it != heat_map.end(); ++heat_it) {
    double d = heat_it->second.heat;
    if (d == 0)
      continue;
    d /= min_heat;

    // Use saturation arithmetic, and ensure that no value is zero.
    uint32 ui = 0;
    if (d >= std::numeric_limits<uint32>::max()) {
      ui = std::numeric_limits<uint32>::max();
    } else {
      ui = static_cast<uint32>(d);
      if (ui == 0)
        ui = 1;
    }

    // Increment the weight associated with the BB-range in the line info.
    if (!line_info->Visit(heat_it->first.start(), heat_it->first.size(), ui)) {
      LOG(ERROR) << "LineInfo::Visit failed.";
      return false;
    }
  }

  return true;
}

// Output the given @p heat_map to the given @p file in CSV format.
bool OutputHeatMap(const HeatMap& heat_map, FILE* file) {
  if (::fprintf(file, "RVA, Size, Compiland, Function, Heat\n") <= 0)
    return false;
  HeatMap::const_iterator it = heat_map.begin();
  for (; it != heat_map.end(); ++it) {
    if (::fprintf(file,
                  "0x%08X, %d, %s, %s, %.10e\n",
                  it->first.start().value(),
                  it->first.size(),
                  it->second.compiland->c_str(),
                  it->second.function->c_str(),
                  it->second.heat) <= 0) {
      return false;
    }
  }
  return true;
}

// A type used for converting NameHeatMaps to a sorted vector.
typedef std::pair<double, const std::string*> HeatNamePair;

// Comparator for heat-name pairs, sorting by decreasing heat then increasing
// name.
struct HeatNamePairComparator {
  bool operator()(const HeatNamePair& hnp1, const HeatNamePair& hnp2) const {
    if (hnp1.first > hnp2.first)
      return true;
    if (hnp1.first < hnp2.first)
      return false;
    return *hnp1.second < *hnp2.second;
  }
};

// Output the given @p name_heat_map to the given @p file in CSV format.
// The column header that is output will depend on the @p aggregation_level.
bool OutputNameHeatMap(SampleGrinder::AggregationLevel aggregation_level,
                       const SampleGrinder::NameHeatMap& name_heat_map,
                       FILE* file) {
  DCHECK(aggregation_level == SampleGrinder::kCompiland ||
         aggregation_level == SampleGrinder::kFunction);
  const char* name = "Compiland";
  if (aggregation_level == SampleGrinder::kFunction)
    name = "Function";
  if (::fprintf(file, "%s, Heat\n", name) <= 0)
    return false;

  std::vector<HeatNamePair> heat_name_pairs;
  heat_name_pairs.reserve(name_heat_map.size());

  SampleGrinder::NameHeatMap::const_iterator it = name_heat_map.begin();
  for (; it != name_heat_map.end(); ++it) {
    heat_name_pairs.push_back(HeatNamePair(it->second, it->first));
  }

  std::sort(heat_name_pairs.begin(),
            heat_name_pairs.end(),
            HeatNamePairComparator());

  for (size_t i = 0; i < heat_name_pairs.size(); ++i) {
    const HeatNamePair& hnp = heat_name_pairs[i];
    if (::fprintf(file, "%s, %.10e\n", hnp.second->c_str(), hnp.first) <= 0)
      return false;
  }

  return true;
}

}  // namespace

// NOTE: This must be kept in sync with SampleGrinder::AggregationLevel.
const char* SampleGrinder::kAggregationLevelNames[] = {
    "basic-block", "function", "compiland", "line" };
COMPILE_ASSERT(arraysize(SampleGrinder::kAggregationLevelNames) ==
                   SampleGrinder::kAggregationLevelMax,
               AggregationLevelNames_out_of_sync);

const char SampleGrinder::kAggregationLevel[] = "aggregation-level";
const char SampleGrinder::kImage[] = "image";

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
    bool known_level = false;
    for (size_t i = 0; i < arraysize(kAggregationLevelNames); ++i) {
      if (LowerCaseEqualsASCII(s, kAggregationLevelNames[i])) {
        known_level = true;
        aggregation_level_ = static_cast<AggregationLevel>(i);
        break;
      }
    }

    if (!known_level) {
      LOG(ERROR) << "Unknown aggregation level: " << s << ".";
      return false;
    }
  }

  // Parse the image parameter, and initialize information about the image of
  // interest.
  image_path_ = command_line->GetSwitchValuePath(kImage);
  if (image_path_.empty()) {
    if (aggregation_level_ == kBasicBlock) {
      LOG(ERROR) << "Must specify --image in basic-block mode.";
      return false;
    }
  } else {
    if (!image_.Init(image_path_)) {
      LOG(ERROR) << "Failed to parse image \"" << image_path_.value() << "\".";
      return false;
    }
    image_.GetSignature(&image_signature_);
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

  // Bail if no data has been processed.
  if (module_data_.empty()) {
    if (!image_path_.empty()) {
      LOG(ERROR) << "No sample data was found for module \""
                 << image_path_.value() << "\".";
      return false;
    } else {
      LOG(ERROR) << "No sample data encountered.";
      return false;
    }
  }

  // Process each module.
  ModuleDataMap::const_iterator mod_it = module_data_.begin();
  for (; mod_it != module_data_.end(); ++mod_it) {
    LOG(INFO) << "Processing aggregate samples for module \""
              << mod_it->second.module_path.value() << "\".";

    // Build an empty heat map. How exactly we do this depends on the
    // aggregation mode.
    bool empty_heat_map_built = false;
    if (aggregation_level_ == kLine) {
      // In line aggregation mode we simply extract line info from the PDB.
      empty_heat_map_built = BuildEmptyHeatMap(
          mod_it->second.module_path, &line_info_, &heat_map_);
    } else {
      // In basic-block, function and compiland aggregation mode we decompose
      // the image to get compilands, functions and basic blocks.
      // TODO(chrisha): We shouldn't need full decomposition for this.
      empty_heat_map_built = BuildEmptyHeatMap(
          mod_it->first, mod_it->second, &string_table_, &heat_map_);
    }

    if (!empty_heat_map_built) {
      LOG(ERROR) << "Unable to build empty heat map for module \""
                  << mod_it->second.module_path.value() << "\".";
      return false;
    }

    // Populate the heat map by pouring the sample data into it. If any samples
    // did not map to code blocks then output a warning.
    double total = 0.0;
    double orphaned = IncrementHeatMapFromModuleData(
        mod_it->second, &heat_map_, &total);
    if (orphaned > 0) {
      LOG(WARNING) << base::StringPrintf("%.2f%% (%.4f s) ",
                                          orphaned / total,
                                          orphaned)
                    << "samples were orphaned for module \""
                    << mod_it->second.module_path.value() << "\".";
    }

    if (aggregation_level_ == kFunction || aggregation_level_ == kCompiland) {
      LOG(INFO) << "Rolling up basic-block heat to \""
                << kAggregationLevelNames[aggregation_level_] << "\" level.";
      RollUpByName(aggregation_level_, heat_map_, &name_heat_map_);
      // We can clear the heat map as it was only needed as an intermediate.
      heat_map_.Clear();
    } else if (aggregation_level_ == kLine) {
      LOG(INFO) << "Rolling up basic-block heat to lines.";
      if (!RollUpToLines(heat_map_, &line_info_)) {
        LOG(ERROR) << "Failed to roll-up heat to lines.";
        return false;
      }
      // We can clear the heat map as it was only needed as an intermediate.
      heat_map_.Clear();
    }
  }

  return true;
}

bool SampleGrinder::OutputData(FILE* file) {
  // If the aggregation level is basic-block, then output the data in the
  // HeatMap.
  bool success = false;
  if (aggregation_level_ == kBasicBlock) {
    success = OutputHeatMap(heat_map_, file);
  } else if (aggregation_level_ == kFunction ||
             aggregation_level_ == kCompiland) {
    // If we've aggregated by function or compiland then output the data in
    // the NameHeatMap.
    success = OutputNameHeatMap(aggregation_level_, name_heat_map_, file);
  } else {
    // Otherwise, we're aggregating to lines and we output cache-grind formatted
    // line-info data.
    DCHECK_EQ(kLine, aggregation_level_);
    CoverageData coverage_data;
    coverage_data.Add(line_info_);
    success = WriteCacheGrindCoverageFile(coverage_data, file);
  }

  if (!success) {
    LOG(ERROR) << "Failed to write to file.";
    return false;
  }

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

  // Filter based on the image of interest, if provided.
  if (!image_path_.empty()) {
    if (image_signature_.module_size != module_info->module_size ||
        image_signature_.module_checksum != module_info->module_checksum ||
        image_signature_.module_time_date_stamp !=
            module_info->module_time_date_stamp) {
      LOG(INFO) << "Skipping sample data for module \""
                << module_info->path << "\".";
      return;
    }
  }

  // Get the summary data associated with this module.
  ModuleData* module_data = GetModuleData(
      base::FilePath(module_info->path), data);

  LOG(INFO) << "Aggregating sample info for module \""
            << module_data->module_path.value() << "\".";

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

double SampleGrinder::IncrementHeatMapFromModuleData(
    const SampleGrinder::ModuleData& module_data,
    HeatMap* heat_map,
    double* total_samples) {
  DCHECK(heat_map != NULL);

  double orphaned_samples = 0.0;
  double temp_total_samples = 0.0;

  // We walk through the sample buckets, and for each one we find the range of
  // heat map entries that intersect with it. We then divide up the heat to
  // each of these ranges in proportion to the size of their intersection.
  core::RelativeAddress rva_bucket(module_data.bucket_start);
  HeatMap::iterator it = heat_map->begin();
  size_t i = 0;
  for (; i < module_data.buckets.size(); ++i) {
    // Advance the current heat map range as long as it's strictly to the left
    // of the current bucket.
    while (it != heat_map->end() && it->first.end() <= rva_bucket)
      ++it;
    if (it == heat_map->end())
      break;

    // If the current heat map range is strictly to the right of the current
    // bucket then those samples have nowhere to be distributed.
    if (rva_bucket + module_data.bucket_size <= it->first.start()) {
      // Tally them up as orphaned samples.
      orphaned_samples += module_data.buckets[i];
    } else {
      // Otherwise we heat map ranges that overlap the current bucket.

      // Advance the current heat map range until we're strictly to the right
      // of the current bucket.
      HeatMap::iterator it_end = it;
      ++it_end;
      while (it_end != heat_map->end() &&
          it_end->first.start() < rva_bucket + module_data.bucket_size) {
        ++it_end;
      }

      // Find the total size of the intersections, to be used as a scaling
      // value for distributing the samples. This is done so that *all* of the
      // samples are distributed, as the bucket may span space that is not
      // covered by any heat map ranges.
      size_t total_intersection = 0;
      for (HeatMap::iterator it2 = it; it2 != it_end; ++it2) {
        total_intersection += IntersectionSize(it2->first,
            rva_bucket, module_data.bucket_size);
      }

      // Now distribute the samples to the various ranges.
      for (HeatMap::iterator it2 = it; it2 != it_end; ++it2) {
        size_t intersection = IntersectionSize(it2->first,
            rva_bucket, module_data.bucket_size);
        it2->second.heat += intersection * module_data.buckets[i] /
            total_intersection;
      }
    }

    // Advance past the current bucket.
    temp_total_samples += module_data.buckets[i];
    rva_bucket += module_data.bucket_size;
  }

  // Pick up any trailing orphaned buckets.
  for (; i < module_data.buckets.size(); ++i) {
    orphaned_samples += module_data.buckets[i];
    temp_total_samples += module_data.buckets[i];
  }

  if (total_samples != NULL)
    *total_samples = temp_total_samples;

  return orphaned_samples;
}

void SampleGrinder::RollUpByName(AggregationLevel aggregation_level,
                                 const HeatMap& heat_map,
                                 NameHeatMap* name_heat_map) {
  DCHECK(aggregation_level == kFunction || aggregation_level == kCompiland);
  DCHECK(name_heat_map != NULL);

  HeatMap::const_iterator it = heat_map.begin();
  for (; it != heat_map.end(); ++it) {
    const std::string* name = it->second.function;
    if (aggregation_level == kCompiland)
      name = it->second.compiland;

    NameHeatMap::iterator nhm_it = name_heat_map->insert(
        std::make_pair(name, 0.0)).first;
    nhm_it->second += it->second.heat;
  }
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
