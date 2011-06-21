# Copyright 2011 Google Inc.
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
      'target_name': 'core_lib',
      'type': 'static_library',
      'sources': [
        'address.cc',
        'address.h',
        'address_space.cc',
        'address_space.h',
        'basic_block_disassembler.cc',
        'basic_block_disassembler.h',
        'block_graph.cc',
        'block_graph.h',
        'disassembler.cc',
        'disassembler.h',
        'random_number_generator.cc',
        'random_number_generator.h',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/distorm/distorm.gyp:distorm',
      ],
    },
    {
      'target_name': 'core_unittests',
      'type': 'executable',
      'sources': [
        'address_unittest.cc',
        'address_space_unittest.cc',
        'basic_block_disassembler_unittest.cc',
        'basic_block_test_code.asm',
        'block_graph_unittest.cc',
        'core_unittests_main.cc',
        'disassembler_test_code.asm',
        'disassembler_unittest.cc',
      ],
      'dependencies': [
        'core_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/third_party/distorm/distorm.gyp:distorm',
      ],
      'rules': [
        {
          'rule_name': 'Assemble',
          'msvs_cygwin_shell': 0,
          'extension': 'asm',
          'inputs': [],
          'outputs': [
            '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
          ],
          'action': [
            'ml',
            '-safeseh',
            '-Zi',
            '-Fo', '<(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj',
            '-c', '<(RULE_INPUT_PATH)',
          ],
          'process_outputs_as_sources': 0,
          'message': 'Assembling <(RULE_INPUT_PATH) to <(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj.',
        },
      ],
    },
  ],
}
