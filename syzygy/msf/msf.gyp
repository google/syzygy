# Copyright 2015 Google Inc. All Rights Reserved.
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
      'target_name': 'msf_lib',
      'type': 'static_library',
      'sources': [
        'msf_byte_stream.h',
        'msf_byte_stream_impl.h',
        'msf_constants.cc',
        'msf_constants.h',
        'msf_data.h',
        'msf_decl.h',
        'msf_file.h',
        'msf_file_impl.h',
        'msf_file_stream.h',
        'msf_file_stream_impl.h',
        'msf_reader.h',
        'msf_reader_impl.h',
        'msf_stream.h',
        'msf_stream_impl.h',
        'msf_writer.h',
        'msf_writer_impl.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
    },
    {
      'target_name': 'msf_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
    },
    {
      'target_name': 'msf_unittests',
      'type': 'executable',
      'sources': [
        'msf_byte_stream_unittest.cc',
        'msf_file_stream_unittest.cc',
        'msf_file_unittest.cc',
        'msf_reader_unittest.cc',
        'msf_stream_unittest.cc',
        'msf_writer_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'msf_lib',
        'msf_unittest_utils',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
