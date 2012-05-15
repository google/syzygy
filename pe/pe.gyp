# Copyright 2012 Google Inc.
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
      # This target serves the purpose of making it easy to
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
        'msvs_settings': {
          'VCLinkerTool': {
            'AdditionalLibraryDirectories': [
              '$(VSInstallDir)/DIA SDK/lib',
            ],
            # GYP has a bug or misfeature whereby a library dependency used
            # from another GYP file in a different directory picks up the path
            # to that directory, so instead of using 'library', we specify the
            # library dependency here.
            'AdditionalDependencies': [
              'diaguids.lib',
            ],
          },
        },
      },
    },
    {
      'target_name': 'pe_lib',
      'type': 'static_library',
      'sources': [
        'dia_browser.cc',
        'dia_browser.h',
        'dia_util.cc',
        'dia_util.h',
        'dia_util_internal.h',
        'decompose_app.cc',
        'decompose_app.h',
        'decomposer.cc',
        'decomposer.h',
        'dos_stub.asm',
        'find.cc',
        'find.h',
        'image_layout.cc',
        'image_layout.h',
        'image_layout_builder.cc',
        'image_layout_builder.h',
        'image_source_map.cc',
        'image_source_map.h',
        'metadata.cc',
        'metadata.h',
        'pdb_info.cc',
        'pdb_info.h',
        'pe_data.h',
        'pe_file.h',
        'pe_file.cc',
        'pe_file_parser.cc',
        'pe_file_parser.h',
        'pe_file_writer.cc',
        'pe_file_writer.h',
        'pe_utils.cc',
        'pe_utils.h',
        'pe_relinker.cc',
        'pe_relinker.h',
      ],
      'dependencies': [
        'dia_sdk',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        '<(DEPTH)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(DEPTH)/syzygy/block_graph/orderers/block_graph_orderers.gyp:'
            'block_graph_orderers_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_lib',
        '<(DEPTH)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(DEPTH)/third_party/distorm/distorm.gyp:distorm',
        '<(DEPTH)/third_party/pcre/pcre.gyp:pcre_lib',
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
          'message': 'Assembling <(RULE_INPUT_PATH) to '
                     '<(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj.',
        },
      ],
      'all_dependent_settings': {
        'msvs_settings': {
          'VCLinkerTool': {
            # GYP has a bug or misfeature whereby a library dependency used
            # from another GYP file in a different directory picks up the path
            # to that directory, so instead of using 'library', we specify the
            # library dependency here.
            'AdditionalDependencies': [
              'imagehlp.lib',
            ],
          },
        },
      },
    },
    {
      'target_name': 'pe_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.h',
        'unittest_util.cc',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/block_graph/block_graph.gyp:block_graph_unittest_lib',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'pe_unittests',
      'type': 'executable',
      'sources': [
        'decompose_app_unittest.cc',
        'decomposer_unittest.cc',
        'dia_browser_unittest.cc',
        'dia_util_unittest.cc',
        'find_unittest.cc',
        'image_layout_builder_unittest.cc',
        'image_layout_unittest.cc',
        'image_source_map_unittest.cc',
        'metadata_unittest.cc',
        'pdb_info_unittest.cc',
        'pe_file_unittest.cc',
        'pe_file_parser_unittest.cc',
        'pe_file_writer_unittest.cc',
        'pe_unittests_main.cc',
        'pe_utils_unittest.cc',
        'pe_relinker_unittest.cc',
      ],
      'dependencies': [
        'pe_lib',
        'test_dll',
        'pe_unittest_utils',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/block_graph/block_graph.gyp:block_graph_unittest_lib',
        '<(DEPTH)/syzygy/block_graph/orderers/block_graph_orderers.gyp:'
            'block_graph_orderers_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/pe/orderers/pe_orderers.gyp:pe_orderers_lib',
        '<(DEPTH)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_lib',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'test_dll',
      'type': 'loadable_module',
      'sources': [
        'test_dll.cc',
        'test_dll.def',
        'test_dll_label_test_func.asm',
      ],
      'dependencies': [
        'export_dll',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # We delay load ole32 purely to test delay load PE parsing.
          'DelayLoadDLLs': [
            'ole32.dll',
          ],
        },
      },
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
          'message': 'Assembling <(RULE_INPUT_PATH) to '
                     '<(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj.',
        },
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
        'Common_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              # This corresponds to /PROFILE, which ensures that the
              # PDB file contains a FIXUP stream.
              # TODO(chrisha): Move this to base.gypi so everything links
              #     with this flag.
              'Profile': 'true',
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
      'target_name': 'decompose_image_to_text',
      'type': 'executable',
      'sources': [
        'decompose_image_to_text.cc',
      ],
      'dependencies': [
        'pe_lib',
        '<(DEPTH)/base/base.gyp:base',
      ],
      'run_as': {
        'working_directory': '$(ConfigurationDir)',
        'action': [
          '$(TargetPath)',
          '--image=test_dll.dll'
        ],
      },
    },
    {
      'target_name': 'decompose',
      'type': 'executable',
      'sources': [
        'decompose_main.cc',
        'decompose.rc',
      ],
      'dependencies': [
        'pe_lib',
        '<(DEPTH)/base/base.gyp:base',
      ],
      'run_as': {
        'working_directory': '$(ConfigurationDir)',
        'action': [
          '$(TargetPath)',
          '--image=test_dll.dll'
        ],
      },
    },

  ]
}
