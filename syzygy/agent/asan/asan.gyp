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
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:logger_rpc_lib',
        '<(src)/syzygy/trace/protocol/protocol.gyp:protocol_lib',
      ],
    },
    {
      'target_name': 'asan_rtl',
      'type': 'loadable_module',
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
        'asan_rtl',
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
