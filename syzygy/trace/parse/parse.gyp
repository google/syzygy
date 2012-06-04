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
      'target_name': 'parse_lib',
      'type': 'static_library',
      'sources': [
        'parse_engine.cc',
        'parse_engine.h',
        'parse_engine_rpc.cc',
        'parse_engine_rpc.h',
        'parse_utils.cc',
        'parse_utils.h',
        'parser.h',
        'parser.cc',
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
      ],
    },
    {
      'target_name': 'dump_trace',
      'type': 'executable',
      'sources': [
        'dump_trace_main.cc',
      ],
      'dependencies': [
        'parse_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
    {
      'target_name': 'parse_unittests',
      'type': 'executable',
      'sources': [
        'parse_engine_rpc_unittest.cc',
        'parse_engine_unittest.cc',
        'parse_utils_unittest.cc',
        'unittests_main.cc',
      ],
      'dependencies': [
        'parse_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        # TODO(siggi,rogerm): Remove these "backward" dependencies.
        '<(DEPTH)/syzygy/agent/call_trace/call_trace.gyp:call_trace_client',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(DEPTH)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(DEPTH)/syzygy/trace/service/service.gyp:rpc_service_lib',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
  ],
}
