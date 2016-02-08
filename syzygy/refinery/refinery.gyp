# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

{
  'variables': {
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'refinery',
      'type': 'none',
      'dependencies': [
        'analyzers/analyzers.gyp:*',
        'core/core.gyp:*',
        'process_state/process_state.gyp:*',
        'validators/validators.gyp:*',
      ],
    },
    {
      'target_name': 'refinery_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        'process_state/process_state.gyp:process_state_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'refinery_unittests',
      'type': 'executable',
      'sources': [
        'analyzers/analyzer_factory_unittest.cc',
        'analyzers/analysis_runner_unittest.cc',
        'analyzers/exception_analyzer_unittest.cc',
        'analyzers/heap_analyzer_unittest.cc',
        'analyzers/memory_analyzer_unittest.cc',
        'analyzers/module_analyzer_unittest.cc',
        'analyzers/teb_analyzer_unittest.cc',
        'analyzers/thread_analyzer_unittest.cc',
        'analyzers/type_propagator_analyzer_unittest.cc',
        'analyzers/unloaded_module_analyzer_unittest.cc',
        'core/address_unittest.cc',
        'core/addressed_data_unittest.cc',
        'detectors/lfh_entry_detector_unittest.cc',
        'process_state/layer_data_unittest.cc',
        'process_state/process_state_unittest.cc',
        'process_state/process_state_util_unittest.cc',
        'symbols/simple_cache_unittest.cc',
        'symbols/symbol_provider_unittest.cc',
        'symbols/symbol_provider_util_unittest.cc',
        'types/type_unittest.cc',
        'types/type_repository_unittest.cc',
        'types/typed_data_unittest.cc',
        'types/dia_crawler_unittest.cc',
        'types/pdb_crawler_unittest.cc',
        'types/type_namer_unittest.cc',
        'validators/exception_handler_validator_unittest.cc',
        'validators/vftable_ptr_validator_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'analyzers/analyzers.gyp:analyzers_lib',
        'core/core.gyp:refinery_core_lib',
        'detectors/detectors.gyp:detectors_lib',
        'detectors/detectors.gyp:detectors_unittest_utils',
        'process_state/process_state.gyp:process_state_lib',
        'symbols/symbols.gyp:symbols_lib',
        'refinery_unittest_utils',
        'testing/testing.gyp:refinery_testing_lib',
        'types/types.gyp:types_lib',
        'types/types.gyp:types_unittest_utils',
        'validators/validators.gyp:validators_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/common/common.gyp:common_unittest_utils',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/syzygy/minidump/minidump.gyp:minidump_lib',
        '<(src)/syzygy/minidump/minidump.gyp:minidump_unittest_utils',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Disable support for large address spaces. This is only required for
          # PdbCrawlerVTableTest.TestGetVFTableRVAs which needs to run an
          # instrumented dll.
          'LargeAddressAware': 1,
        },
      },
    },
    {
      'target_name': 'refinery_stack_unittests',
      'type': 'executable',
      'sources': [
        'analyzers/stack_analysis_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'analyzers/analyzers.gyp:analyzers_lib',
        'core/core.gyp:refinery_core_lib',
        'process_state/process_state.gyp:process_state_lib',
        'symbols/symbols.gyp:symbols_lib',
        'refinery_unittest_utils',
        'types/types.gyp:types_lib',
        'validators/validators.gyp:validators_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/common/common.gyp:common_unittest_utils',
        '<(src)/syzygy/minidump/minidump.gyp:minidump_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
      'defines': [
        'SYZYGY_UNITTESTS_USE_LONG_TIMEOUT=1',
      ],
    },
    {
      'target_name': 'run_refinery',
      'type': 'executable',
      'sources': [
        'run_refinery_main.cc',
      ],
      'dependencies': [
        'analyzers/analyzers.gyp:analyzers_lib',
        'core/core.gyp:refinery_core_lib',
        'process_state/process_state.gyp:process_state_lib',
        'types/types.gyp:types_lib',
        'validators/validators.gyp:validators_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/minidump/minidump.gyp:minidump_lib',
      ],
    },
  ]
}
