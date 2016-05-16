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

#include "syzygy/refinery/analyzers/analyzer_factory.h"

#include <string>

#include "gtest/gtest.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

namespace {

static const char kInvalidAnalyzerName[] = "FooBarAnalyzer";

static ProcessState::LayerEnum kAllLayers[] = {
#define LAYER_CONSTANT_ENUM(name) ProcessState::name##Layer,

    PROCESS_STATE_LAYERS(LAYER_CONSTANT_ENUM)

#undef LAYER_CONSTANT_ENUM
};

class StaticAnalyzerFactoryTest : public testing::Test {
 public:
  void SetUp() override {
    list_.GetAnalyzerNames(&analyzer_names_);
    EXPECT_NE(0u, analyzer_names_.size());
  }

  const AnalyzerFactory::AnalyzerNames& analyzer_names() const {
    return analyzer_names_;
  }
  const StaticAnalyzerFactory& list() const { return list_; }

 private:
  AnalyzerFactory::AnalyzerNames analyzer_names_;
  StaticAnalyzerFactory list_;
};

}  // namespace

TEST_F(StaticAnalyzerFactoryTest,
       CreateAnalyzersSucceedsForValidAnalyzerNames) {
  for (const auto& name : analyzer_names()) {
    std::unique_ptr<Analyzer> analyzer(list().CreateAnalyzer(name));

    ASSERT_TRUE(analyzer.get());
    ASSERT_EQ(name, analyzer->name());
  }
}

TEST_F(StaticAnalyzerFactoryTest, CreateAnalyzerFailsForInvalidAnalyzerName) {
  std::unique_ptr<Analyzer> analyzer(
      list().CreateAnalyzer(kInvalidAnalyzerName));
  ASSERT_FALSE(analyzer.get());
}

TEST_F(StaticAnalyzerFactoryTest, GetInputLayersSucceedsForValidAnalyzerNames) {
  for (const auto& name : analyzer_names()) {
    AnalyzerFactory::Layers layers;
    ASSERT_TRUE(list().GetInputLayers(name, &layers));
  }
}

TEST_F(StaticAnalyzerFactoryTest, GetInputLayersFailsForInvalidAnalyzerName) {
  AnalyzerFactory::Layers layers;
  ASSERT_FALSE(list().GetInputLayers(kInvalidAnalyzerName, &layers));
}

TEST_F(StaticAnalyzerFactoryTest,
       GetOutputLayersSucceedsForValidAnalyzerNames) {
  for (const auto& name : analyzer_names()) {
    AnalyzerFactory::Layers layers;
    ASSERT_TRUE(list().GetOutputLayers(name, &layers));
  }
}

TEST_F(StaticAnalyzerFactoryTest,
       GetGetAnalyzersInputtingHasAnalyzersForLayers) {
  for (ProcessState::LayerEnum layer : kAllLayers) {
    AnalyzerFactory::AnalyzerNames analyzer_names;
    list().GetAnalyzersInputting(layer, &analyzer_names);

    if (layer == ProcessState::HeapAllocationLayer ||
        layer == ProcessState::HeapMetadataLayer) {
      EXPECT_EQ(0u, analyzer_names.size()) << "Some analyzers input "
                                           << ProcessState::LayerName(layer);
    } else {
      EXPECT_NE(0u, analyzer_names.size()) << "No analyzers input "
                                           << ProcessState::LayerName(layer);
    }
  }
}

TEST_F(StaticAnalyzerFactoryTest,
       GetGetAnalyzersOutputtingHasAnalyzersForLayers) {
  for (ProcessState::LayerEnum layer : kAllLayers) {
    AnalyzerFactory::AnalyzerNames analyzer_names;
    list().GetAnalyzersOutputting(layer, &analyzer_names);
    EXPECT_NE(0u, analyzer_names.size()) << "No analyzers output "
                                         << ProcessState::LayerName(layer);
  }
}

}  // namespace refinery
