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
        'integration_tests_dll',
        '<(src)/syzygy/agent/asan/asan.gyp:syzyasan_rtl',
        '<(src)/syzygy/agent/basic_block_entry/basic_block_entry.gyp:'
            'basic_block_entry_client',
        '<(src)/syzygy/agent/call_trace/call_trace.gyp:call_trace_client',
        '<(src)/syzygy/agent/coverage/coverage.gyp:coverage_client',
        '<(src)/syzygy/agent/profiler/profiler.gyp:profile_client',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/grinder/grinder.gyp:grinder_lib',
        '<(src)/syzygy/instrument/instrument.gyp:instrument_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(src)/testing/gtest.gyp:gtest',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # ASAN agent is compiled without large address spaces to allow a
          # memory optimization on the shadow memory. Agents should run in both
          # modes, thus in the long term, we should remove this.
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
    {
      'target_name': 'integration_tests_dll',
      'type': 'loadable_module',
      'sources': [
        'asan_check_tests.h',
        'asan_interceptors_tests.h',
        'asan_interceptors_tests.cc',
        'bb_entry_tests.cc',
        'bb_entry_tests.h',
        'behavior_tests.cc',
        'behavior_tests.h',
        'coverage_tests.cc',
        'coverage_tests.h',
        'integration_tests_dll.cc',
        'integration_tests_dll.def',
        'integration_tests_dll.h',
        'integration_tests_dll.rc',
        'profile_tests.cc',
        'profile_tests.h',
      ],
      'dependencies': [
        '<(src)/syzygy/common/common.gyp:syzygy_version',
        '<(src)/syzygy/pe/pe.gyp:export_dll',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # ASAN agent is compiled without large address spaces to allow a
          # memory optimization on the shadow memory. Agents should run in both
          # modes, thus in the long term, we should remove this.
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
      # We more or less want this to always be a release-style executable
      # to facilitate instrumentation.
      # We have to do this per configuration, as base.gypi specifies
      # this per-config, which binds tighter than the defaults above.
      'configurations': {
        'Debug_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              # This corresponds to /INCREMENTAL:NO. With incremental linking
              # enabled, every function resolves to a location in a jump table
              # which jumps to the function proper. This gets in the way of
              # disassembly.
              'LinkIncremental': '1',
              # Ensure that the checksum present in the header of the binaries
              # is set.
              'SetChecksum': 'true',
            },
            'VCCLCompilerTool': {
              'BasicRuntimeChecks': '0',
              # ASAN needs the application to be linked with the release static
              # runtime library. Otherwise, memory allocation functions are
              # wrapped and hide memory bugs like overflow/underflow.
              'RuntimeLibrary':  '0', # 0 = /MT (nondebug static)
              # Disable the iterator debugging for this project. We need to do
              # this because we link against the release version of the C
              # runtime library, and the iterator debugging relies on some
              # functions present only in the debug version of the library.
              'PreprocessorDefinitions': ['_HAS_ITERATOR_DEBUGGING=0'],
            },
          },
        },
        'Common_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              # This corresponds to /PROFILE, which ensures that the
              # PDB file contains a FIXUP stream.
              # TODO(chrisha): Move this to base.gypi so everything links
              #     with this flag.
              'Profile': 'true',
            },
          },
        },
      },
    },
  ],
}
