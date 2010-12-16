# Copyright 2010 Google Inc.
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
      'target_name': 'image_util',
      'type': 'static_library',
      'sources': [
        'address.h',
        'address.cc',
        'address_space.h',
        'address_space.cc',
        'block_graph.h',
        'block_graph.cc',
        'disassembler.h',
        'disassembler.cc',
        'pe_file.h',
        'pe_file.cc',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/distorm/distorm.gyp:distorm',
      ],
    },
    {
      'target_name': 'image_util_unittests',
      'type': 'executable',
      'sources': [
        'address_unittest.cc',
        'address_space_unittest.cc',
        'block_graph_unittest.cc',
        'disassembler_test_code.asm',
        'disassembler_unittest.cc',
        'image_util_unittests_main.cc',
        'pe_file_unittest.cc',
      ],
      'dependencies': [
        'image_util',
        'test_dll',
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
            '-Fo', '<(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj',
            '-c', '<(RULE_INPUT_PATH)',
          ],
          'process_outputs_as_sources': 0,
          'message': 'Assembling <(RULE_INPUT_PATH) to <(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj.',
        },
      ],
    },
    {
      'target_name': 'test_dll',
      'type': 'loadable_module',
      'sources': [
        'test_dll.cc',
        'test_dll.def',
      ],
      'dependencies': [
        'export_dll',
      ],
      # We more or less want this to always be a release-style executable
      # to facilitate instrumentation.
      # We have to do this per configuration, as base.gypi specifies
      # this per-config, which binds tighter than the defaults above.
      'configurations': {
        'Debug_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              # This corresponds to /INCREMENTAL:NO. With incremental linking
              # enabled, every function resolves to a location in a jump table
              # which jumps to the function proper. This gets in the way of
              # disassembly.
              'LinkIncremental': '1',
            },
            'VCCLCompilerTool': {
              'BasicRuntimeChecks': '0',
            },
          },
        },
      },
    },
    {
      'target_name': 'export_dll',
      'type': 'shared_library',
      'sources': [
        'export_dll.cc',
        'export_dll.def',
      ],
    }
  ]
}
