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
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:call_trace_rpc_lib',
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
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
    {
      'target_name': 'parse_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
      ],
    },
    {
      'target_name': 'parse_unittests',
      'type': 'executable',
      'sources': [
        'parse_engine_rpc_unittest.cc',
        'parse_engine_unittest.cc',
        'parse_utils_unittest.cc',
        'parser_unittest.cc',
        'unittests_main.cc',
      ],
      'dependencies': [
        'parse_lib',
        'parse_unittest_utils',
        '<(src)/base/base.gyp:base',
        # TODO(siggi,rogerm): Remove these "backward" dependencies.
        '<(src)/syzygy/agent/call_trace/call_trace.gyp:call_trace_client',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/service/service.gyp:rpc_service_lib',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
  ],
}
