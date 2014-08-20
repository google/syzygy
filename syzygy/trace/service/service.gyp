# Copyright 2012 Google Inc. All Rights Reserved.
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
      'target_name': 'rpc_service_lib',
      'type': 'static_library',
      'sources': [
        'buffer_consumer.h',
        'buffer_pool.cc',
        'buffer_pool.h',
        'mapped_buffer.cc',
        'mapped_buffer.h',
        'process_info.cc',
        'process_info.h',
        'service.cc',
        'service.h',
        'service_rpc_impl.cc',
        'service_rpc_impl.h',
        'session.cc',
        'session.h',
        'session_trace_file_writer.cc',
        'session_trace_file_writer.h',
        'session_trace_file_writer_factory.cc',
        'session_trace_file_writer_factory.h',
        'trace_file_writer.cc',
        'trace_file_writer.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:call_trace_rpc_lib',
      ],
    },
    {
      'target_name': 'rpc_service_unittests',
      'type': 'executable',
      'sources': [
        'mapped_buffer_unittest.cc',
        'process_info_unittest.cc',
        'rpc_service_unittests_main.cc',
        'service_unittest.cc',
        'session_unittest.cc',
        'trace_file_writer_unittest.cc',
      ],
      'dependencies': [
        'call_trace_service_exe',
        'rpc_service_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(src)/syzygy/trace/client/client.gyp:rpc_client_lib',
        '<(src)/syzygy/trace/service/service.gyp:rpc_service_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
      ],
    },
    {
      'target_name': 'call_trace_service_exe',
      'product_name': 'call_trace_service',
      'type': 'executable',
      'sources': [
        'service_main.cc',
        'service.rc',
      ],
      'dependencies': [
        'rpc_service_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Enable support for large address spaces.
          'LargeAddressAware': 2,
        },
      },
    },
  ],
}
