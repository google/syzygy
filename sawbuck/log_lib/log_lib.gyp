# Copyright 2009 Google Inc.
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
  'includes': [
    '../../build/common.gypi',
  ],
  'target_defaults': {
    'include_dirs': [
      '../..',
    ],
  },
  'targets': [
    {
      'target_name': 'log_lib',
      'type': 'static_library',
      'sources': [
        'buffer_parser.cc',
        'buffer_parser.h',
        'kernel_log_consumer.cc',
        'kernel_log_consumer.h',
        'log_consumer.cc',
        'log_consumer.h',
        'process_info_service.cc',
        'process_info_service.h',
        'symbol_lookup_service.cc',
        'symbol_lookup_service.h',
      ],
      'dependencies': [
        '../../base/base.gyp:base',
      ],
    },
    {
      'target_name': 'test_common',
      'type': 'static_library',
      'sources': [
        'kernel_log_unittest_data.h',
        'kernel_log_unittest_data.cc',
      ],
      'dependencies': [
        '../../base/base.gyp:base',
      ],      
    },
    {
      'target_name': 'make_test_data',
      'type': 'executable',
      'sources': [
        'make_test_data.cc',
      ],
      'dependencies': [
        'test_common',
        '../../base/base.gyp:base',
        '../../testing/gtest.gyp:gtest',
      ],      
    },
    {
      'target_name': 'log_lib_unittests',
      'type': 'executable',
      'sources': [
        'buffer_parser_unittest.cc',
        'kernel_log_consumer_unittest.cc',
        'log_consumer_unittest.cc',
        'log_lib_unittest_main.cc',
        'process_info_service_unittest.cc',
        'symbol_lookup_service_unittest.cc',
      ],
      'dependencies': [
        'log_lib',
        'test_common',
        '../sym_util/sym_util.gyp:sym_util',
        '../../base/base.gyp:base',
        '../../testing/gmock.gyp:gmock',
        '../../testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'dump_logs',
      'type': 'executable',
      'sources': [
        'dump_logs_main.cc',
      ],
      'dependencies': [
        'log_lib',
        '../../base/base.gyp:base',
      ],          
    },
    {
      'target_name': 'test_logger',
      'type': 'executable',
      'sources': [
        'test_logger.cc',
      ],
      'dependencies': [
        '../../base/base.gyp:base',
      ],
    },
  ]
}
