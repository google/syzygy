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
      # This target servese the purpose of making it easy to
      # propagate the settings required for users of the DIA SDK.
      'target_name': 'dia_sdk',
      'type': 'none',
      # We copy the msdia90.dll into the build directory for conveninence.
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)',
          'files': [
            '$(VSInstallDir)/DIA SDK/bin/msdia90.dll',
          ],
        },
      ],
      'all_dependent_settings': {
        'include_dirs': [
          '$(VSInstallDir)/DIA SDK/include',
        ],
        'libraries': [
          'diaguids.lib',
        ],
        'msvs_settings': {
          'VCLinkerTool': {
            'AdditionalLibraryDirectories': [
              '$(VSInstallDir)/DIA SDK/lib',
            ],
          },
        },
      },
    },
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
        'decomposer.h',
        'decomposer.cc',
        'disassembler.h',
        'disassembler.cc',
        'pe_file.h',
        'pe_file.cc',
        'pe_file_builder.h',
        'pe_file_builder.cc',
        'pe_file_parser.h',
        'pe_file_parser.cc',
        'pe_file_writer.h',
        'pe_file_writer.cc',
      ],
      'dependencies': [
        'dia_sdk',
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
        'decomposer_unittest.cc',
        'disassembler_test_code.asm',
        'disassembler_unittest.cc',
        'image_util_unittests_main.cc',
        'pdb_byte_stream_unittest.cc',
        'pdb_file_stream_unittest.cc',
        'pdb_reader_unittest.cc',
        'pdb_stream_unittest.cc',
        'pdb_util_unittest.cc',
        'pdb_writer_unittest.cc',
        'pe_file_builder_unittest.cc',
        'pe_file_unittest.cc',
        'pe_file_parser_unittest.cc',
        'pe_file_writer_unittest.cc',
        'unittest_util.h',
        'unittest_util.cc',
      ],
      'dependencies': [
        'image_util',
        'pdb_lib',
        'test_dll',
        '../log_lib/log_lib.gyp:log_lib',
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
    },
    {
      'target_name': 'DecomposeImageToText',
      'type': 'executable',
      'sources': [
        'decompose_image_to_text.cc',
      ],
      'dependencies': [
        'image_util',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/distorm/distorm.gyp:distorm',
      ],
    },
    {
      'target_name': 'RecomposePDB',
      'type': 'executable',
      'sources': [
        'recompose_pdb.cc',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
      ],
    },
    {
      'target_name': 'pdb_lib',
      'type': 'static_library',
      'sources': [
        'pdb_byte_stream.cc',
        'pdb_byte_stream.h',
        'pdb_constants.cc',
        'pdb_constants.h',
        'pdb_data.h',
        'pdb_file_stream.cc',
        'pdb_file_stream.h',
        'pdb_reader.cc',
        'pdb_reader.h',
        'pdb_stream.cc',
        'pdb_stream.h',
        'pdb_util.cc',
        'pdb_util.h',
        'pdb_writer.cc',
        'pdb_writer.h',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
      ],
    },
  ]
}
