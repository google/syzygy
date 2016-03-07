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
//
// Declares the sample grinder, which processes trace files containing
// TraceSampleData records. It can aggregate to a variety of targets
// (basic blocks, functions, compilands, lines), and output to a variety of
// formats (CSV, KCacheGrind).

#ifndef SYZYGY_GRINDER_GRINDERS_SAMPLE_GRINDER_H_
#define SYZYGY_GRINDER_GRINDERS_SAMPLE_GRINDER_H_

#include "syzygy/core/address_space.h"
#include "syzygy/core/string_table.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/grinder.h"
#include "syzygy/pe/pe_file.h"

namespace grinder {
namespace grinders {

// This class processes trace files containing TraceSampleData records and
// produces estimates of block/function/compiland heat.
class SampleGrinder : public GrinderInterface {
 public:
  // The level of aggregation to be used in processing samples.
  enum AggregationLevel {
    kBasicBlock,
    kFunction,
    kCompiland,
    kLine,
    kAggregationLevelMax,  // Must be last.
  };

  // The names of the aggregation levels. These must be kept in sync with
  // AggregationLevel.
  static const char* kAggregationLevelNames[];

  SampleGrinder();
  ~SampleGrinder();

  // @name SampleInterface implementation.
  // @{
  virtual bool ParseCommandLine(const base::CommandLine* command_line) override;
  virtual void SetParser(Parser* parser) override;
  virtual bool Grind() override;
  virtual bool OutputData(FILE* file) override;
  // @}

  // @name ParseEventHandler implementation.
  // @{
  // Override of the OnProcessStarted callback. This is required to get
  // the system clock rate for scaling frequency data.
  virtual void OnProcessStarted(base::Time time,
                                DWORD process_id,
                                const TraceSystemInfo* data) override;
  // Override of the OnSampleData callback.
  virtual void OnSampleData(base::Time Time,
                            DWORD process_id,
                            const TraceSampleData* data) override;
  // @}

  // @name Parameter names.
  // @{
  static const char kAggregationLevel[];
  static const char kImage[];
  // @}

  // Forward declarations. These are public so that they are accessible by
  // anonymous helper functions.
  struct ModuleKey;
  struct ModuleData;

  // Some type definitions. There are public so that they are accessible by
  // anonymous helper functions.

  // We store some metadata for each basic-block in an image, allowing us to
  // roll up the heat based on different categories.
  struct BasicBlockData {
    const std::string* compiland;
    const std::string* function;
    double heat;
  };
  // This is the type of address-space that is used for representing estimates
  // of heat calculated from aggregate sample data.
  typedef core::AddressSpace<core::RelativeAddress, size_t, BasicBlockData>
      HeatMap;

  // This is the final aggregate type used to represent heat as rolled up to
  // named objects (compilands or functions).
  typedef std::map<const std::string*, double> NameHeatMap;

 protected:
  // Finds or creates the sample data associated with the given module.
  ModuleData* GetModuleData(
      const base::FilePath& module_path,
      const TraceSampleData* sample_data);

  // Upsamples the provided @p module_data so that it has at least as many
  // buckets as the @p sample_data. If the resolution is already sufficient
  // this does nothing.
  // @param sample_data The sample data to be used as a reference.
  // @param module_data The module data to be potentially upsampled.
  // @note This is exposed for unit testing.
  static void UpsampleModuleData(
      const TraceSampleData* sample_data,
      SampleGrinder::ModuleData* module_data);

  // Updates the @p module_data with the samples from @p sample_data. The
  // @p module_data must already be at sufficient resolution to accept the
  // data in @p sample_data. This can fail if the @p sample_data and the
  // @p module_data do not have consistent metadata.
  // @param clock_rate The clock rate to be used in scaling the sample data.
  // @param sample_data The sample data to be added.
  // @param module_data The module data to be incremented.
  // @returns True on success, false otherwise.
  static bool IncrementModuleData(
      double clock_rate,
      const TraceSampleData* sample_data,
      SampleGrinder::ModuleData* module_data);

  // Given a populated @p heat_map and aggregate @p module_data, estimates heat
  // for each range in the @p heat_map. The values represent an estimate of
  // amount of time spent in the range, in seconds.
  // @param module_data Aggregate module data.
  // @param heat A pre-populated address space representing the basic blocks of
  //     the module in question.
  // @param total_samples The total number of samples processed will be returned
  //     here. This is optional and may be NULL.
  // @returns the total weight of orphaned samples that were unable to be mapped
  //     to any range in the heat map.
  static double IncrementHeatMapFromModuleData(
      const SampleGrinder::ModuleData& module_data,
      HeatMap* heat_map,
      double* total_samples);

  // Given a populated @p heat_map performs an aggregation of the heat based
  // on function or compiland names.
  // @param aggregation_level The aggregation level. Must be one of
  //     kFunction or kCompiland.
  // @param heat_map The BB heat map to be aggregated.
  // @param name_heat_map The named heat map to be populated.
  static void RollUpByName(AggregationLevel aggregation_level,
                           const HeatMap& heat_map,
                           NameHeatMap* name_heat_map);

  // The aggregation level to be used in processing samples.
  AggregationLevel aggregation_level_;

  // If image_path_ is not empty, then this data is used as a filter for
  // processing.
  base::FilePath image_path_;
  pe::PEFile image_;
  pe::PEFile::Signature image_signature_;

  // Points to the parser that is feeding us events. Used to get module
  // information.
  Parser* parser_;

  // Set to true if any call to OnIndexedFrequency fails. Processing will
  // continue with a warning that results may be partial.
  bool event_handler_errored_;

  // The clock rate that is currently in force. This is used for scaling
  // sample values.
  double clock_rate_;

  // As we parse sample data we update a running tally at the finest bucket
  // size observed in trace files.
  typedef std::map<ModuleKey, ModuleData> ModuleDataMap;
  ModuleDataMap module_data_;

  // These are used for holding final results. They are populated by Grind()
  // when the aggregation mode is anything except 'line'.
  core::StringTable string_table_;
  HeatMap heat_map_;
  NameHeatMap name_heat_map_;

  // Used only in 'line' aggregation mode. Populated by Grind().
  LineInfo line_info_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SampleGrinder);
};

struct SampleGrinder::ModuleKey {
  size_t module_size;
  uint32_t module_checksum;
  uint32_t module_time_date_stamp;

  bool operator<(const ModuleKey& rhs) const;
};

struct SampleGrinder::ModuleData {
  ModuleData::ModuleData() : bucket_size(0) {}

  base::FilePath module_path;
  uint32_t bucket_size;
  core::RelativeAddress bucket_start;
  std::vector<double> buckets;
};

}  // namespace grinders
}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDERS_SAMPLE_GRINDER_H_
