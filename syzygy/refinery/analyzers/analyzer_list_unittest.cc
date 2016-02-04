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
static const char* kAnalyzerNames[] = {
#define DECLARE_ANALYZER_NAME(name) #name "Analyzer",
    ANALYZER_LIST(DECLARE_ANALYZER_NAME)
#undef DECLARA_ANALYZER_NAME
};

static_assert(arraysize(kAnalyzerNames) > 0, "No analyzer names!");

static const char kInvalidAnalyzerName[] = "FooBarAnalyzer";
}  // namespace

TEST(AnalyzerListTest, CreateAnalyzersSucceedsForValidAnalyzerNames) {
  for (const char* name : kAnalyzerNames) {
    scoped_ptr<Analyzer> analyzer(AnalyzerList::CreateAnalyzer(name));

    ASSERT_TRUE(analyzer.get());
    ASSERT_STREQ(name, analyzer->name());
  }
}

TEST(AnalyzerListTest, CreateAnalyzersFailsForInvalidAnalyzerName) {
  scoped_ptr<Analyzer> analyzer(
      AnalyzerList::CreateAnalyzer(kInvalidAnalyzerName));
  ASSERT_FALSE(analyzer.get());
}

TEST(AnalyzerListTest, GetInputLayersSucceedsForValidAnalyzerNames) {
  for (const char* name : kAnalyzerNames) {
    AnalyzerList::Layers layers;
    ASSERT_TRUE(AnalyzerList::GetInputLayers(name, &layers));
  }
}

TEST(AnalyzerListTest, GetInputLayersFailsForInvalidAnalyzerName) {
  AnalyzerList::Layers layers;
  ASSERT_FALSE(AnalyzerList::GetInputLayers(kInvalidAnalyzerName, &layers));
}

TEST(AnalyzerListTest, GetOutputLayersSucceedsForValidAnalyzerNames) {
  for (const char* name : kAnalyzerNames) {
    AnalyzerList::Layers layers;
    ASSERT_TRUE(AnalyzerList::GetOutputLayers(name, &layers));
  }
}

TEST(AnalyzerListTest, GetOutputLayersFailsForInvalidAnalyzerName) {
  AnalyzerList::Layers layers;
  ASSERT_FALSE(AnalyzerList::GetOutputLayers(kInvalidAnalyzerName, &layers));
}

}  // namespace refinery
