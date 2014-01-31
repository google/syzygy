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
      'target_name': 'rpc_client_lib',
      'type': 'static_library',
      'sources': [
        'client_utils.cc',
        'client_utils.h',
        'rpc_session.cc',
        'rpc_session.h',
      ],
      'dependencies': [
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
      ],
    },
    {
      'target_name': 'rpc_client_lib_unittests',
      'type': 'executable',
      'sources': [
        'client_utils_unittest.cc',
        'rpc_client_lib_unittests_main.cc',
      ],
      'dependencies': [
        'rpc_client_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/protocol/protocol.gyp:protocol_lib',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
      ],
    },
  ],
}
