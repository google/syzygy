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
      'target_name': 'core_lib',
      'type': 'static_library',
      'sources': [
        'address.cc',
        'address.h',
        'address_filter.h',
        'address_filter_impl.h',
        'address_space.cc',
        'address_space.h',
        'address_space_internal.h',
        'assembler.cc',
        'assembler.h',
        'disassembler.cc',
        'disassembler.h',
        'disassembler_util.cc',
        'disassembler_util.h',
        'file_util.cc',
        'file_util.h',
        'json_file_writer.cc',
        'json_file_writer.h',
        'random_number_generator.cc',
        'random_number_generator.h',
        'register_internal.h',
        'register.cc',
        'register.h',
        'section_offset_address.cc',
        'section_offset_address.h',
        'serialization.cc',
        'serialization.h',
        'serialization_impl.h',
        'string_table.cc',
        'string_table.h',
        'zstream.cc',
        'zstream.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/third_party/distorm/distorm.gyp:distorm',
        '<(src)/third_party/zlib/zlib.gyp:zlib',
      ],
    },
    {
      'target_name': 'core_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'core_unittests',
      'type': 'executable',
      'includes': ['../build/masm.gypi'],
      'sources': [
        'address_unittest.cc',
        'address_filter_unittest.cc',
        'address_space_unittest.cc',
        'core_unittests_main.cc',
        'assembler_unittest.cc',
        'disassembler_test_code.asm',
        'disassembler_unittest.cc',
        'disassembler_util_unittest.cc',
        'file_util_unittest.cc',
        'json_file_writer_unittest.cc',
        'register_unittest.cc',
        'section_offset_address_unittest.cc',
        'serialization_unittest.cc',
        'string_table_unittest.cc',
        'unittest_util_unittest.cc',
        'zstream_unittest.cc',
      ],
      'dependencies': [
        'core_lib',
        'core_unittest_utils',
        '<(src)/base/base.gyp:base',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/third_party/distorm/distorm.gyp:distorm',
        '<(src)/third_party/zlib/zlib.gyp:zlib',
      ],
    },
  ],
}
