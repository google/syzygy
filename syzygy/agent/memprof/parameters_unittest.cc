// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/memprof/parameters.h"

#include "base/environment.h"
#include "gtest/gtest.h"

namespace agent {
namespace memprof {

TEST(ParametersTest, SetDefaults) {
  Parameters p = {};
  SetDefaultParameters(&p);
  EXPECT_EQ(kDefaultStackTraceTracking, p.stack_trace_tracking);
  EXPECT_EQ(kDefaultSerializeTimestamps, p.serialize_timestamps);
  EXPECT_EQ(kDefaultHashContentsAtFree, p.hash_contents_at_free);
}

TEST(ParametersTest, ParseInvalidStackTraceTracking) {
  Parameters p = {};
  SetDefaultParameters(&p);
  std::string str("--stack-trace-tracking=foo");
  EXPECT_FALSE(ParseParameters(str, &p));
}

TEST(ParametersTest, ParseMinimalCommandLine) {
  Parameters p = {};
  SetDefaultParameters(&p);
  std::string str("");
  EXPECT_TRUE(ParseParameters(str, &p));
  EXPECT_EQ(kDefaultStackTraceTracking, p.stack_trace_tracking);
  EXPECT_EQ(kDefaultSerializeTimestamps, p.serialize_timestamps);
  EXPECT_EQ(kDefaultHashContentsAtFree, p.hash_contents_at_free);
}

TEST(ParametersTest, ParseMaximalCommandLine) {
  Parameters p = {};
  SetDefaultParameters(&p);
  std::string str("--stack-trace-tracking=emit "
                  "--serialize-timestamps "
                  "--hash-contents-at-free");
  EXPECT_TRUE(ParseParameters(str, &p));
  EXPECT_EQ(kTrackingEmit, p.stack_trace_tracking);
  EXPECT_TRUE(p.serialize_timestamps);
  EXPECT_TRUE(p.hash_contents_at_free);
}

TEST(ParametersTest, ParseNoEnvironment) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_NE(nullptr, env.get());
  env->UnSetVar(kParametersEnvVar);

  Parameters p = {};
  SetDefaultParameters(&p);
  EXPECT_TRUE(ParseParametersFromEnv(&p));
  EXPECT_EQ(kDefaultStackTraceTracking, p.stack_trace_tracking);
  EXPECT_EQ(kDefaultSerializeTimestamps, p.serialize_timestamps);
  EXPECT_EQ(kDefaultHashContentsAtFree, p.hash_contents_at_free);
}

TEST(ParametersTest, ParseEmptyEnvironment) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_NE(nullptr, env.get());
  env->SetVar(kParametersEnvVar, "");

  Parameters p = {};
  SetDefaultParameters(&p);
  EXPECT_TRUE(ParseParametersFromEnv(&p));
  EXPECT_EQ(kDefaultStackTraceTracking, p.stack_trace_tracking);
  EXPECT_EQ(kDefaultSerializeTimestamps, p.serialize_timestamps);
  EXPECT_EQ(kDefaultHashContentsAtFree, p.hash_contents_at_free);
}

TEST(ParametersTest, ParseInvalidEnvironment) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_NE(nullptr, env.get());
  env->SetVar(kParametersEnvVar, "--stack-trace-tracking=foo");

  Parameters p = {};
  SetDefaultParameters(&p);
  EXPECT_FALSE(ParseParametersFromEnv(&p));
}

TEST(ParametersTest, ParseValidEnvironment) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_NE(nullptr, env.get());
  env->SetVar(kParametersEnvVar,
              "--stack-trace-tracking=emit --serialize-timestamps");

  Parameters p = {};
  SetDefaultParameters(&p);
  EXPECT_TRUE(ParseParametersFromEnv(&p));
  EXPECT_EQ(kTrackingEmit, p.stack_trace_tracking);
  EXPECT_TRUE(p.serialize_timestamps);
}

}  // namespace memprof
}  // namespace agent
