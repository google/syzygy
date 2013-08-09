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
// (basic blocks, functions, compilands), and output to a variety of formats
// (JSON, CSV, LCOV).
//
// TODO(chrisha): Implement the actual rolling up to bbs/functions/compilands
//     and produce output.

#ifndef SYZYGY_GRINDER_GRINDERS_SAMPLE_GRINDER_H_
#define SYZYGY_GRINDER_GRINDERS_SAMPLE_GRINDER_H_

#include "syzygy/core/address.h"
#include "syzygy/grinder/grinder.h"

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
  };

  SampleGrinder();
  ~SampleGrinder();

  // @name SampleInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE;
  virtual void SetParser(Parser* parser) OVERRIDE;
  virtual bool Grind() OVERRIDE;
  virtual bool OutputData(FILE* file) OVERRIDE;
  // @}

  // @name ParseEventHandler implementation.
  // @{
  // Override of the OnProcessStarted callback. This is required to get
  // the system clock rate for scaling frequency data.
  virtual void OnProcessStarted(base::Time time,
                                DWORD process_id,
                                const TraceSystemInfo* data) OVERRIDE;
  // Override of the OnSampleData callback.
  virtual void OnSampleData(base::Time Time,
                            DWORD process_id,
                            const TraceSampleData* data) OVERRIDE;
  // @}

  // @name Parameter names.
  // @{
  static const char kAggregationLevel[];
  // @}

  // Forward declarations. These are public so that they are accessible by
  // anonymous helper functions.
  struct ModuleKey;
  struct ModuleData;

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

  // The aggregation level to be used in processing samples.
  AggregationLevel aggregation_level_;

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

 private:
  DISALLOW_COPY_AND_ASSIGN(SampleGrinder);
};

struct SampleGrinder::ModuleKey {
  size_t module_size;
  uint32 module_checksum;
  uint32 module_time_date_stamp;

  bool operator<(const ModuleKey& rhs) const;
};

struct SampleGrinder::ModuleData {
  ModuleData::ModuleData() : bucket_size(0) {}

  base::FilePath module_path;
  uint32 bucket_size;
  core::RelativeAddress bucket_start;
  std::vector<double> buckets;
};

}  // namespace grinders
}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDERS_SAMPLE_GRINDER_H_
