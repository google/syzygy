# Copyright 2012 Google Inc.
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
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'rpc_service_lib',
      'type': 'static_library',
      'sources': [
        'buffer_pool.cc',
        'buffer_pool.h',
        'process_info.cc',
        'process_info.h',
        'service.cc',
        'service.h',
        'service_rpc_impl.cc',
        'session.cc',
        'session.h',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
      ],
    },
    {
      'target_name': 'rpc_service_unittests',
      'type': 'executable',
      'sources': [
        'process_info_unittests.cc',
        'service_unittests.cc',
        'session_unittests.cc',
        'rpc_service_unittests_main.cc',
      ],
      'dependencies': [
        'rpc_service_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(DEPTH)/syzygy/trace/client/client.gyp:rpc_client_lib',
        '<(DEPTH)/syzygy/trace/service/service.gyp:rpc_service_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
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
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
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
