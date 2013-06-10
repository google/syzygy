# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

{
  'targets': [
    {
      'target_name': 'integration_tests',
      'type': 'executable',
      'sources': [
        'integration_tests.rc',
        'integration_tests_main.cc',
        'instrument_integration_test.cc',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/asan/asan.gyp:asan_rtl',
        '<(src)/syzygy/agent/basic_block_entry/basic_block_entry.gyp:'
            'basic_block_entry_client',
        '<(src)/syzygy/agent/call_trace/call_trace.gyp:call_trace_client',
        '<(src)/syzygy/agent/coverage/coverage.gyp:coverage_client',
        '<(src)/syzygy/agent/profiler/profiler.gyp:profile_client',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/grinder/grinder.gyp:grinder_lib',
        '<(src)/syzygy/instrument/instrument.gyp:instrument_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:test_dll',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(src)/testing/gtest.gyp:gtest',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # ASAN agent is compiled without large address spaces to allow an
          # memory optimization on the shadow memory. Agents should run in both
          # mode, thus on long term, we should remove this.
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
  ],
}
