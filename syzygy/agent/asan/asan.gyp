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
  'targets': [
    {
      'target_name': 'asan_rtl_lib',
      'type': 'static_library',
      'sources': [
        'asan_heap.cc',
        'asan_heap.h',
        'asan_logger.cc',
        'asan_logger.h',
        'asan_rtl_impl.cc',
        'asan_rtl_impl.h',
        'asan_runtime.cc',
        'asan_runtime.h',
        'asan_shadow.cc',
        'asan_shadow.h',
        'stack_capture.cc',
        'stack_capture.h',
        'stack_capture_cache.cc',
        'stack_capture_cache.h',
      ],
      'dependencies': [
        '<(src)/syzygy/trace/rpc/rpc.gyp:logger_rpc_lib',
        '<(src)/syzygy/trace/protocol/protocol.gyp:protocol_lib',
      ],
    },
    {
      'target_name': 'asan_rtl',
      'type': 'shared_library',
      'sources': [
        'asan_rtl.cc',
        'asan_rtl.def',
        'asan_rtl.rc',
      ],
      'dependencies': [
        'asan_rtl_lib',
        '<(src)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/common.gyp:syzygy_version',
        '<(src)/syzygy/core/core.gyp:core_lib',
      ],
    },
    {
      # This is an indirect target that allows us to depend on the existence
      # of asan_rtl.dll without causing it be imported by the target.
      'target_name': 'asan_rtl_is_built',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        'asan_rtl',
      ],
      'actions': [
        {
          'action_name': 'touch_asan_rtl_is_built',
          'inputs': [
            '<(PRODUCT_DIR)/asan_rtl.dll',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/asan_rtl_is_built.txt',
          ],
          'action': [
            '<(python_exe)',
            '-c',
            'import sys; open(sys.argv[1], \'wb\')',
            '<(PRODUCT_DIR)/asan_rtl_is_built.txt',
          ],
        }
      ],
    },
    {
      'target_name': 'asan_rtl_unittests',
      'type': 'executable',
      'sources': [
        'asan_heap_unittest.cc',
        'asan_logger_unittest.cc',
        'asan_runtime_unittest.cc',
        'asan_rtl_impl_unittest.cc',
        'asan_rtl_unittest.cc',
        'asan_rtl_unittests_main.cc',
        'asan_shadow_unittest.cc',
        'stack_capture_unittest.cc',
        'stack_capture_cache_unittest.cc',
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        # We can't simply depend on the library itself, as that means it will
        # be imported. We prefer to manually load it at runtime, hence the
        # indirect dependency via a 'none' target.
        'asan_rtl_is_built',
        'asan_rtl_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/trace/logger/logger.gyp:logger_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
       ],
    },
  ],
}
