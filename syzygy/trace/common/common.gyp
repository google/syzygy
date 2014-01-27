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
      'target_name': 'trace_unittest_utils',
      'type': 'static_library',
      'dependencies': [
        '<(src)/syzygy/trace/service/service.gyp:rpc_service_lib',
        '<(src)/testing/gtest.gyp:gtest'
      ],
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
    },
    {
      'target_name': 'trace_common_lib',
      'type': 'static_library',
      'sources': [
        'clock.cc',
        'clock.h',
        'service.cc',
        'service.h',
        'service_util.cc',
        'service_util.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/sawbuck/log_lib/log_lib.gyp:log_lib',
      ],
    },
    {
      'target_name': 'trace_common_unittests',
      'type': 'executable',
      'sources': [
        'clock_unittest.cc',
        'common_unittests_main.cc',
        'service_unittest.cc',
        'service_util_unittest.cc',
      ],
      'dependencies': [
        'trace_common_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
