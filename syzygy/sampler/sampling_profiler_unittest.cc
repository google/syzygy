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

#include "syzygy/sampler/sampling_profiler.h"

#include "base/logging.h"
#include "base/win/pe_image.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_version.h"
#include "gtest/gtest.h"

// The address of our image base.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace sampler {

namespace {

class SamplingProfilerTest : public testing::Test {
 public:
  SamplingProfilerTest() : code_start(NULL), code_size(0) {
  }

  virtual void SetUp() {
    process.Set(::OpenProcess(PROCESS_QUERY_INFORMATION,
                              FALSE,
                              ::GetCurrentProcessId()));
    ASSERT_TRUE(process.IsValid());

    base::win::PEImage image(&__ImageBase);

    // Get the address of the .text section, which is the first section output
    // by the VS tools.
    ASSERT_TRUE(image.GetNumSections() > 0);
    const IMAGE_SECTION_HEADER* text_section = image.GetSectionHeader(0);
    ASSERT_EQ(0, strncmp(".text",
                         reinterpret_cast<const char*>(text_section->Name),
                         arraysize(text_section->Name)));
    ASSERT_NE(0U, text_section->Characteristics & IMAGE_SCN_MEM_EXECUTE);

    code_start = reinterpret_cast<uint8*>(&__ImageBase) +
        text_section->VirtualAddress;
    code_size = text_section->Misc.VirtualSize;
  }

 protected:
  base::win::ScopedHandle process;
  void* code_start;
  size_t code_size;
};

}  // namespace

TEST_F(SamplingProfilerTest, Initialize) {
  SamplingProfiler profiler;

  ASSERT_TRUE(profiler.Initialize(process.Get(), code_start, code_size, 8));
}

TEST_F(SamplingProfilerTest, Sample) {
  if (base::win::GetVersion() == base::win::VERSION_WIN8) {
    LOG(INFO) << "Not running test on Windows 8";
    return;
  }
  SamplingProfiler profiler;

  // Initialize with a huge bucket size, aiming for a single bucket.
  ASSERT_TRUE(
      profiler.Initialize(process.Get(), code_start, code_size, 31));

  ASSERT_EQ(1, profiler.buckets().size());
  ASSERT_EQ(0, profiler.buckets()[0]);

  // We use a roomy timeout to make sure this test is not flaky.
  // On the buildbots, there may not be a whole lot of CPU time
  // allotted to our process in this wall-clock time duration,
  // and samples will only accrue while this thread is busy on
  // a CPU core.
  base::TimeDelta spin_time = base::TimeDelta::FromSeconds(10);

  base::TimeDelta save_sampling_interval;
  ASSERT_TRUE(SamplingProfiler::GetSamplingInterval(&save_sampling_interval));

  // Sample every 0.5 millisecs.
  ASSERT_TRUE(SamplingProfiler::SetSamplingInterval(
      base::TimeDelta::FromMicroseconds(500)));

  ASSERT_TRUE(SamplingProfiler::SetSamplingInterval(
      base::TimeDelta::FromMicroseconds(500)));

  // Start the profiler.
  ASSERT_TRUE(profiler.Start());

  // Get a volatile pointer to our bucket to make sure that the compiler
  // doesn't optimize out the test in the loop that follows.
  volatile const ULONG* bucket_ptr = &profiler.buckets()[0];

  // Spin for spin_time wall-clock seconds, or until we get some samples.
  // Note that sleeping isn't going to do us any good, the samples only
  // accrue while we're executing code.
  base::Time start = base::Time::Now();
  base::TimeDelta elapsed;
  do {
    elapsed = base::Time::Now() - start;
  } while ((elapsed < spin_time) && *bucket_ptr == 0);

  // Stop the profiler.
  ASSERT_TRUE(profiler.Stop());

  // Restore the sampling interval we found.
  ASSERT_TRUE(SamplingProfiler::SetSamplingInterval(save_sampling_interval));

  // Check that we got some samples.
  ASSERT_NE(0U, profiler.buckets()[0]);
}

}  // namespace sampler
