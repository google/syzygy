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
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'logger_lib',
      'type': 'static_library',
      'sources': [
        'logger.cc',
        'logger.h',
        'logger_rpc_impl.cc',
        'logger_rpc_impl.h',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:logger_rpc_lib',
      ],
    },
    {
      'target_name': 'logger_unittests',
      'type': 'executable',
      'sources': [
        'logger_unittest.cc',
        'logger_unittests_main.cc',
      ],
      'dependencies': [
        'logger_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],
    },
  ],
}
