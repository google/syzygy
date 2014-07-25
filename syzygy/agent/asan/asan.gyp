# Copyright 2012 Google Inc. All Rights Reserved.
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
  'variables': {
    'chromium_code': 1,
    'system_interceptors_output_base_name': '<(SHARED_INTERMEDIATE_DIR)/'
        'syzygy/agent/asan/asan_system_interceptors',
  },
  'targets': [
    {
      'target_name': 'syzyasan_rtl_lib',
      'type': 'static_library',
      'sources': [
        'asan_crt_interceptors.cc',
        'asan_crt_interceptors.h',
        'asan_heap.cc',
        'asan_heap.h',
        'asan_heap_checker.cc',
        'asan_heap_checker.h',
        'asan_logger.cc',
        'asan_logger.h',
        'asan_rtl_impl.cc',
        'asan_rtl_impl.h',
        'asan_rtl_utils.cc',
        'asan_rtl_utils.h',
        'asan_runtime.cc',
        'asan_runtime.h',
        'asan_system_interceptors.cc',
        'asan_system_interceptors.h',
        'block.cc',
        'block.h',
        'block_impl.h',
        'block_utils.cc',
        'block_utils.h',
        'constants.cc',
        'constants.h',
        'direct_allocation.cc',
        'direct_allocation.h',
        'error_info.cc',
        'error_info.h',
        'heap.h',
        'nested_heap.cc',
        'nested_heap.h',
        'page_allocator.h',
        'page_allocator_impl.h',
        'quarantine.h',
        'shadow.cc',
        'shadow.h',
        'shadow_impl.h',
        'stack_capture.cc',
        'stack_capture.h',
        'stack_capture_cache.cc',
        'stack_capture_cache.h',
        'heaps/large_block_heap.cc',
        'heaps/large_block_heap.h',
        'heaps/simple_block_heap.cc',
        'heaps/simple_block_heap.h',
        'heaps/win_heap.cc',
        'heaps/win_heap.h',
        'quarantines/sharded_quarantine.h',
        'quarantines/sharded_quarantine_impl.h',
        'quarantines/size_limited_quarantine.h',
        'quarantines/size_limited_quarantine_impl.h',
      ],
      'dependencies': [
        'system_interceptors_generator',
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:logger_rpc_lib',
        '<(src)/syzygy/trace/protocol/protocol.gyp:protocol_lib',
      ],
    },
    {
      'target_name': 'syzyasan_rtl',
      'type': 'loadable_module',
      'includes': ['../agent.gypi'],
      'sources': [
        '<(system_interceptors_output_base_name).def.gen',
        'syzyasan_rtl.cc',
        'syzyasan_rtl.rc',
      ],
      'dependencies': [
        'syzyasan_rtl_lib',
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/common.gyp:syzygy_version',
        '<(src)/syzygy/core/core.gyp:core_lib',
      ],
      'configurations': {
        # Override the default imports list at source - apparently the
        # configuration inheritance hierarchy is traversed and settings merged
        # for each target. It's not sufficient here to e.g. override the
        # desired settings in the final, assembled configuration such as
        # 'Debug' or 'Release', as that will only alter their contribution to
        # the project.
        # Note that this is brittle to changes in build/common.gypi.
        'Common_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              'AdditionalDependencies=': [],
              'ModuleDefinitionFile': [
                '<(system_interceptors_output_base_name).def.gen'
              ],
            },
          },
        },
      },
      'msvs_settings': {
        'VCLinkerTool': {
          # Link against the XP-constrained user32 import libraries for
          # kernel32 and user32 of the platform-SDK provided one to avoid
          # inadvertently taking dependencies on post-XP user32 exports.
          'IgnoreDefaultLibraryNames': [
            'user32.lib',
            'kernel32.lib',
          ],
          'AdditionalDependencies=': [
            # Custom import libs.
            'user32.winxp.lib',
            'kernel32.winxp.lib',

            # SDK import libs.
            'dbghelp.lib',
            'psapi.lib',
            'rpcrt4.lib',
          ],
          'AdditionalLibraryDirectories': [
            '<(src)/build/win/importlibs/x86',
            '<(src)/syzygy/build/importlibs/x86',
          ],
          # This module should delay load nothing.
          'DelayLoadDLLs=': [
          ],
          # Force MSVS to produce the same output name as Ninja.
          'ImportLibrary': '$(OutDir)lib\$(TargetFileName).lib'
        },
      },
    },
    {
      'target_name': 'system_interceptors_generator',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'asan_system_interceptor_parser.py',
      ],
      'actions': [
        {
          'action_name': 'generate_syzyasan_system_interceptors',
          'inputs': [
            'syzyasan_rtl.def',
            'asan_system_interceptors_function_list.txt',
          ],
          'outputs': [
            '<(system_interceptors_output_base_name)_impl.h.gen',
            '<(system_interceptors_output_base_name)_instrumentation_filter'
                '.h.gen',
            '<(system_interceptors_output_base_name).def.gen',
          ],
          'action': [
            '<(python_exe)',
            'asan_system_interceptor_parser.py',
            '--output-base=<(system_interceptors_output_base_name)',
            '--overwrite',
            '--def-file=syzyasan_rtl.def',
            'asan_system_interceptors_function_list.txt',
          ],
        },
      ],
    },
    {
      'target_name': 'syzyasan_rtl_unittests',
      'type': 'executable',
      'sources': [
        'asan_crt_interceptors_unittest.cc',
        'asan_heap_checker_unittest.cc',
        'asan_heap_unittest.cc',
        'asan_logger_unittest.cc',
        'asan_runtime_unittest.cc',
        'asan_rtl_impl_unittest.cc',
        'asan_rtl_unittest.cc',
        'asan_rtl_unittests_main.cc',
        'asan_rtl_utils_unittest.cc',
        'asan_system_interceptors_unittest.cc',
        'block_unittest.cc',
        'block_utils_unittest.cc',
        'direct_allocation_unittest.cc',
        'error_info_unittest.cc',
        'nested_heap_unittest.cc',
        'page_allocator_unittest.cc',
        'shadow_unittest.cc',
        'stack_capture_unittest.cc',
        'stack_capture_cache_unittest.cc',
        'unittest_util.cc',
        'unittest_util.h',
        'heaps/large_block_heap_unittest.cc',
        'heaps/simple_block_heap_unittest.cc',
        'heaps/win_heap_unittest.cc',
        'quarantines/sharded_quarantine_unittest.cc',
        'quarantines/size_limited_quarantine_unittest.cc',
      ],
      'dependencies': [
        'syzyasan_rtl_lib',
        'syzyasan_rtl',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/trace/agent_logger/agent_logger.gyp:agent_logger_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
       ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
  ],
}
