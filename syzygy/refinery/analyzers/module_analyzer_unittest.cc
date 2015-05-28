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

#include "syzygy/refinery/analyzers/module_analyzer.h"

#include <stdint.h>

#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

TEST(ModuleAnalyzerTest, AnalyzeMinidump) {
  Minidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));

  ProcessState process_state;

  ModuleAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(minidump, &process_state));

  ModuleLayerPtr module_layer;
  ASSERT_TRUE(process_state.FindLayer(&module_layer));
  ASSERT_LE(1, module_layer->size());
}

TEST(ModuleAnalyzerTest, AnalyzeSyntheticMinidump) {
  // Create a minidump with a single module.
  testing::MinidumpSpecification spec;
  testing::MinidumpSpecification::ModuleSpecification module_spec;
  module_spec.addr = 12345ULL;
  module_spec.size = 75U;
  module_spec.checksum = 23U;
  module_spec.timestamp = 42U;
  module_spec.name = "someModule";
  spec.AddModule(module_spec);

  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath minidump_path;
  ASSERT_TRUE(spec.Serialize(temp_dir, &minidump_path));

  // Analyze it for modules.
  Minidump minidump;
  ASSERT_TRUE(minidump.Open(minidump_path));
  ProcessState process_state;
  ModuleAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(minidump, &process_state));

  // Validate recovered module.
  ModuleLayerPtr module_layer;
  ASSERT_TRUE(process_state.FindLayer(&module_layer));
  ASSERT_EQ(1, module_layer->size());

  std::vector<ModuleRecordPtr> matching_records;
  module_layer->GetRecordsAt(module_spec.addr, &matching_records);
  ASSERT_EQ(1, matching_records.size());
  ASSERT_EQ(AddressRange(module_spec.addr, module_spec.size),
            matching_records[0]->range());
  const Module& module = matching_records[0]->data();
  ASSERT_EQ(module_spec.checksum, module.checksum());
  ASSERT_EQ(module_spec.timestamp, module.timestamp());
  ASSERT_EQ(module_spec.name, module.name());
}

}  // namespace refinery
