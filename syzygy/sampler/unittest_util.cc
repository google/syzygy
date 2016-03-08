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

#include "syzygy/sampler/unittest_util.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/common/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace testing {

namespace {

static uint32_t kDummyModuleAddress = 0x07000000;
static uint32_t kDummyBucketSize = 4;

// Returns the address of 'LabelTestFunc'.
void GetLabelTestFuncAdddress(const pe::PEFile& test_dll_pe_file,
                              pe::PEFile::RelativeAddress* function_rva) {
  DCHECK(function_rva != NULL);

  // Get the address of the exported function.
  pe::PEFile::ExportInfoVector exports;
  ASSERT_TRUE(test_dll_pe_file.DecodeExports(&exports));
  for (size_t i = 0; i < exports.size(); ++i) {
    if (exports[i].name == "LabelTestFunc") {
      *function_rva = exports[i].function;
      break;
    }
  }
  ASSERT_NE(0u, function_rva->value());
}

void InitializeDummyTraceSampleData(
    const trace::common::ClockInfo& clock_info,
    const pe::PEFile& test_dll_pe_file,
    const pe::PEFile::Signature& test_dll_pe_sig,
    std::vector<uint8_t>* buffer) {
  const IMAGE_SECTION_HEADER* text_header =
        test_dll_pe_file.GetSectionHeader(".text");
  ASSERT_TRUE(text_header != NULL);

  // Get the index of the first bucket mapping to LabelTestFunc.
  pe::PEFile::RelativeAddress text_rva(text_header->VirtualAddress);
  pe::PEFile::RelativeAddress function_rva;
  ASSERT_NO_FATAL_FAILURE(GetLabelTestFuncAdddress(test_dll_pe_file,
                                                   &function_rva));
  ASSERT_LE(text_rva, function_rva);
  size_t offset = function_rva.value() - text_rva.value();
  ASSERT_EQ(0u, offset % 4);
  size_t index = offset / 4;

  // Initialize a TraceSampleData record. We make it look like we sampled
  // for 10 seconds at 100 Hz.
  size_t bucket_count =
      (text_header->Misc.VirtualSize + kDummyBucketSize - 1) /
          kDummyBucketSize;

  buffer->resize(offsetof(TraceSampleData, buckets) +
                 sizeof(uint32_t) * bucket_count);
  TraceSampleData* sample_data = reinterpret_cast<TraceSampleData*>(
      buffer->data());

  sample_data->module_base_addr =
      reinterpret_cast<ModuleAddr>(kDummyModuleAddress);
  sample_data->module_size = test_dll_pe_sig.module_size;
  sample_data->module_checksum = test_dll_pe_sig.module_checksum;
  sample_data->module_time_date_stamp =
      test_dll_pe_sig.module_time_date_stamp;
  sample_data->bucket_size = kDummyBucketSize;
  sample_data->bucket_start = reinterpret_cast<ModuleAddr>(
      kDummyModuleAddress + text_header->VirtualAddress);
  sample_data->bucket_count = bucket_count;
  sample_data->sampling_start_time =
      clock_info.tsc_reference - 10 * clock_info.tsc_info.frequency;
  sample_data->sampling_end_time = clock_info.tsc_reference;
  sample_data->sampling_interval = clock_info.tsc_info.frequency / 100;

  // We put 1000 samples (10s of heat) into the first bucket associated with
  // 'LabelTestFunc'.
  sample_data->buckets[index] = 1000;
}

}  // namespace

void WriteDummySamplerTraceFile(const base::FilePath& path) {
  trace::common::ClockInfo clock_info = {};
  trace::common::GetClockInfo(&clock_info);

  base::FilePath test_dll_path = GetOutputRelativePath(kTestDllName);
  pe::PEFile test_dll_pe_file;
  ASSERT_TRUE(test_dll_pe_file.Init(test_dll_path));

  pe::PEFile::Signature test_dll_pe_sig;
  test_dll_pe_file.GetSignature(&test_dll_pe_sig);

  trace::service::TraceFileWriter writer;
  ASSERT_TRUE(writer.Open(path));

  // Write a dummy header.
  trace::service::ProcessInfo process_info;
  ASSERT_TRUE(process_info.Initialize(::GetCurrentProcessId()));
  ASSERT_TRUE(writer.WriteHeader(process_info));

  // Write a dummy module loaded event.
  TraceModuleData module_data = {};
  module_data.module_base_addr =
      reinterpret_cast<ModuleAddr>(kDummyModuleAddress);
  module_data.module_base_size = test_dll_pe_sig.module_size;
  module_data.module_checksum = test_dll_pe_sig.module_checksum;
  module_data.module_time_date_stamp =
      test_dll_pe_sig.module_time_date_stamp;
  wcsncpy(module_data.module_name,
          test_dll_path.value().c_str(),
          arraysize(module_data.module_name));

  ASSERT_NO_FATAL_FAILURE(testing::WriteRecord(
      clock_info.tsc_reference,
      TRACE_PROCESS_ATTACH_EVENT,
      &module_data,
      sizeof(module_data),
      &writer));

  // The TraceSampleData should already be initialized
  std::vector<uint8_t> buffer;
  InitializeDummyTraceSampleData(
      clock_info, test_dll_pe_file, test_dll_pe_sig, &buffer);
  ASSERT_FALSE(buffer.empty());

  // Write the sample data and close the file.
  ASSERT_NO_FATAL_FAILURE(testing::WriteRecord(
      clock_info.tsc_reference,
      TraceSampleData::kTypeId,
      buffer.data(),
      buffer.size(),
      &writer));

  ASSERT_TRUE(writer.Close());
}

}  // namespace testing
