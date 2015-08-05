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
        'instrument_integration_test.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'crash_for_exception_harness',
        'integration_tests_dll',
        'integration_tests_harness',
        'report_crash_with_protobuf_harness',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/agent/asan/asan.gyp:syzyasan_dyn',
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
        '<(src)/syzygy/testing/testing.gyp:testing_lib',
        '<(src)/syzygy/trace/agent_logger/agent_logger.gyp:agent_logger',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/third_party/pcre/pcre.gyp:pcre_lib',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # This test binary is initially compiled without large address
          # support. A second version of it that is LAA aware is created by
          # another build step.
          'LargeAddressAware': 1,
        },
      },
      'defines': [
        'SYZYGY_UNITTESTS_CHECK_MEMORY_MODEL=1',
        'SYZYGY_UNITTESTS_USE_LONG_TIMEOUT=1',
      ],
    },
    {
      'target_name': 'integration_tests_4g',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'dependencies': ['integration_tests'],
      'actions': [
        {
          'action_name': 'make_integration_tests_4g',
          'inputs': [
            '<(src)/syzygy/build/copy_laa.py',
            '<(PRODUCT_DIR)/integration_tests.exe',
          ],
          'outputs': ['<(PRODUCT_DIR)/integration_tests_4g.exe'],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/copy_laa.py',
            '--input=$(OutDir)\\integration_tests.exe',
            '--output=$(OutDir)\\integration_tests_4g.exe',
            '--overwrite',
          ],
        },
      ],
    },
    {
      'target_name': 'integration_tests_dll',
      'type': 'loadable_module',
      'sources': [
        'asan_check_tests.h',
        'asan_interceptors_tests.cc',
        'asan_interceptors_tests.h',
        'asan_page_protection_tests.cc',
        'asan_page_protection_tests.h',
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
        '<(src)/syzygy/pe/pe.gyp:export_dll',
        '<(src)/syzygy/version/version.gyp:syzygy_version',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Asan agent is compiled without large address spaces to allow a
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
              # Asan needs the application to be linked with the release static
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
    {
      'target_name': 'integration_tests_harness',
      'type': 'executable',
      'sources': [
        'integration_tests_harness.cc',
      ],
      'dependencies': [
        'integration_tests_dll',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Asan agent is compiled without large address spaces to allow a
          # memory optimization on the shadow memory. Agents should run in both
          # modes, thus in the long term, we should remove this.
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
    {
      'target_name': 'crash_for_exception_harness',
      'type': 'executable',
      'sources': [
        'crash_for_exception_export.cc',
        'integration_tests_harness.cc',
      ],
      'dependencies': [
        'integration_tests_dll',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/agent/asan/asan.gyp:syzyasan_rtl_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Asan agent is compiled without large address spaces to allow a
          # memory optimization on the shadow memory. Agents should run in both
          # modes, thus in the long term, we should remove this.
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
    {
      'target_name': 'report_crash_with_protobuf_harness',
      'type': 'executable',
      'sources': [
        'crash_for_exception_export.cc',
        'report_crash_with_protobuf_export.cc',
        'integration_tests_harness.cc',
      ],
      'dependencies': [
        'integration_tests_dll',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/agent/asan/asan.gyp:syzyasan_rtl_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Asan agent is compiled without large address spaces to allow a
          # memory optimization on the shadow memory. Agents should run in both
          # modes, thus in the long term, we should remove this.
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
  ],
}
