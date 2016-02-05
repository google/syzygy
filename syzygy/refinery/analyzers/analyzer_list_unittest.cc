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

#include "syzygy/refinery/analyzers/analyzer_list.h"

#include <string>

#include "gtest/gtest.h"

namespace refinery {

namespace {

static const char kInvalidAnalyzerName[] = "FooBarAnalyzer";

class StaticAnalyzerListTest : public testing::Test {
 public:
  void SetUp() override {
    list_.GetAnalyzerNames(&analyzer_names_);
    EXPECT_NE(0u, analyzer_names_.size());
  }

  const AnalyzerList::AnalyzerNames& analyzer_names() const {
    return analyzer_names_;
  }
  const StaticAnalyzerList& list() const { return list_; }

 private:
  AnalyzerList::AnalyzerNames analyzer_names_;
  StaticAnalyzerList list_;
};

}  // namespace

TEST_F(StaticAnalyzerListTest, CreateAnalyzersSucceedsForValidAnalyzerNames) {
  for (const auto& name : analyzer_names()) {
    scoped_ptr<Analyzer> analyzer(list().CreateAnalyzer(name));

    ASSERT_TRUE(analyzer.get());
    ASSERT_EQ(name, analyzer->name());
  }
}

TEST_F(StaticAnalyzerListTest, CreateAnalyzersFailsForInvalidAnalyzerName) {
  scoped_ptr<Analyzer> analyzer(list().CreateAnalyzer(kInvalidAnalyzerName));
  ASSERT_FALSE(analyzer.get());
}

TEST_F(StaticAnalyzerListTest, GetInputLayersSucceedsForValidAnalyzerNames) {
  for (const auto& name : analyzer_names()) {
    AnalyzerList::Layers layers;
    ASSERT_TRUE(list().GetInputLayers(name, &layers));
  }
}

TEST_F(StaticAnalyzerListTest, GetInputLayersFailsForInvalidAnalyzerName) {
  AnalyzerList::Layers layers;
  ASSERT_FALSE(list().GetInputLayers(kInvalidAnalyzerName, &layers));
}

TEST_F(StaticAnalyzerListTest, GetOutputLayersSucceedsForValidAnalyzerNames) {
  for (const auto& name : analyzer_names()) {
    AnalyzerList::Layers layers;
    ASSERT_TRUE(list().GetOutputLayers(name, &layers));
  }
}

TEST_F(StaticAnalyzerListTest, GetOutputLayersFailsForInvalidAnalyzerName) {
  AnalyzerList::Layers layers;
  ASSERT_FALSE(list().GetOutputLayers(kInvalidAnalyzerName, &layers));
}

}  // namespace refinery
