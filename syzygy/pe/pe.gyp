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
    'dia_sdk_dir': '$(VSInstallDir)/DIA SDK',
    'conditions': [
      ['MSVS_VERSION=="2013"', {
        'dia_sdk_dll': 'msdia120.dll',
      }],
      ['MSVS_VERSION=="2015"', {
        'dia_sdk_dll': 'msdia140.dll',
      }],
    ],
  },
  'targets': [
    {
      # This target serves the purpose of making it easy to
      # propagate the settings required for users of the DIA SDK.
      'target_name': 'dia_sdk',
      'type': 'none',
      # We copy the msdiaXXX.dll into the build directory for convenience.
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)',
          'files': [
            '<(dia_sdk_dir)/bin/<(dia_sdk_dll)',
          ],
        },
      ],
      'all_dependent_settings': {
        'include_dirs': [
          '<(dia_sdk_dir)/include',
        ],
        'msvs_settings': {
          'VCLinkerTool': {
            'conditions': [
              ['target_arch == "ia32"', {
                'AdditionalLibraryDirectories': ['<(dia_sdk_dir)/lib']
              }, {
                'AdditionalLibraryDirectories': ['<(dia_sdk_dir)/lib/amd64']
              }]
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
      'target_name': 'symsrv_dll_copy',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)',
          'files': [
            '<(src)/third_party/debugging_tools/files/SymSrv.dll',
            '<(src)/third_party/debugging_tools/files/symsrv.yes',
          ],
        },
      ],
    },
    {
      'target_name': 'pe_lib',
      'type': 'static_library',
      'sources': [
        'coff_decomposer.cc',
        'coff_decomposer.h',
        'coff_file.cc',
        'coff_file.h',
        'coff_file_writer.cc',
        'coff_file_writer.h',
        'coff_image_layout_builder.cc',
        'coff_image_layout_builder.h',
        'coff_relinker.cc',
        'coff_relinker.h',
        'coff_transform_policy.cc',
        'coff_transform_policy.h',
        'coff_utils.cc',
        'coff_utils.h',
        'cvinfo_ext.h',
        'dia_browser.cc',
        'dia_browser.h',
        'dia_util.cc',
        'dia_util.h',
        'dia_util_internal.h',
        'decomposer.cc',
        'decomposer.h',
        'find.cc',
        'find.h',
        'image_filter.cc',
        'image_filter.h',
        'image_layout.cc',
        'image_layout.h',
        'image_source_map.cc',
        'image_source_map.h',
        'hot_patching_decomposer.cc',
        'hot_patching_decomposer.h',
        'hot_patching_writer.cc',
        'hot_patching_writer.h',
        'metadata.cc',
        'metadata.h',
        'pdb_info.cc',
        'pdb_info.h',
        'pe_coff_file.h',
        'pe_coff_file_impl.h',
        'pe_coff_image_layout_builder.cc',
        'pe_coff_image_layout_builder.h',
        'pe_coff_relinker.cc',
        'pe_coff_relinker.h',
        'pe_data.h',
        'pe_file.h',
        'pe_file_impl.h',
        'pe_file_parser.cc',
        'pe_file_parser.h',
        'pe_file_writer.cc',
        'pe_file_writer.h',
        'pe_image_layout_builder.cc',
        'pe_image_layout_builder.h',
        'pe_utils.cc',
        'pe_utils.h',
        'pe_utils_impl.h',
        'pe_relinker.cc',
        'pe_relinker.h',
        'pe_relinker_util.cc',
        'pe_relinker_util.h',
        'pe_structs.h',
        'pe_transform_policy.cc',
        'pe_transform_policy.h',
        'relinker.h',
        'serialization.cc',
        'serialization.h',
      ],
      'conditions': [
        ['target_arch == "ia32"', {
          'sources': [
            'dos_stub.asm',
            'dos_stub.cc',
            'dos_stub.h',
          ]
        }]
      ],
      'dependencies': [
        'dia_sdk',
        'symsrv_dll_copy',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(src)/syzygy/block_graph/orderers/block_graph_orderers.gyp:'
            'block_graph_orderers_lib',
        '<(src)/syzygy/block_graph/transforms/block_graph_transforms.gyp:'
            'block_graph_transforms_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(src)/syzygy/version/version.gyp:version_lib',
        '<(src)/third_party/distorm/distorm.gyp:distorm',
        '<(src)/third_party/pcre/pcre.gyp:pcre_lib',
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
      'target_name': 'pe_app_lib',
      'type': 'static_library',
      'sources': [
        'decompose_image_to_text_app.cc',
        'decompose_image_to_text_app.h',
        'decompose_app.cc',
        'decompose_app.h',
      ],
      'dependencies': [
        'pe_lib',
        '<(src)/syzygy/application/application.gyp:application_lib',
        '<(src)/syzygy/version/version.gyp:syzygy_version',
      ],
    },
    {
      'target_name': 'pe_unittest_utils',
      'type': 'static_library',
      'sources': [
        'hot_patching_unittest_util.h',
        'hot_patching_unittest_util.cc',
        'unittest_util.h',
        'unittest_util.cc',
      ],
      'dependencies': [
        'pe_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/common.gyp:common_unittest_utils',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_unittest_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'pe_unittests',
      'type': 'executable',
      'defines': [
        'TEST_DLL_OBJECT_FILE="obj/syzygy/pe/test_dll.test_dll.obj"',
      ],
      'sources': [
        'coff_decomposer_unittest.cc',
        'coff_file_unittest.cc',
        'coff_file_writer_unittest.cc',
        'coff_image_layout_builder_unittest.cc',
        'coff_relinker_unittest.cc',
        'coff_transform_policy_unittest.cc',
        'coff_utils_unittest.cc',
        'cvinfo_ext_unittest.cc',
        'decompose_app_unittest.cc',
        'decompose_image_to_text_unittest.cc',
        'decomposer_unittest.cc',
        'dia_browser_unittest.cc',
        'dia_util_unittest.cc',
        'find_unittest.cc',
        'image_filter_unittest.cc',
        'image_layout_unittest.cc',
        'image_source_map_unittest.cc',
        'hot_patching_decomposer_unittest.cc',
        'hot_patching_writer_unittest.cc',
        'metadata_unittest.cc',
        'pdb_info_unittest.cc',
        'pe_coff_file_unittest.cc',
        'pe_coff_image_layout_builder_unittest.cc',
        'pe_coff_relinker_unittest.cc',
        'pe_file_unittest.cc',
        'pe_file_parser_unittest.cc',
        'pe_file_writer_unittest.cc',
        'pe_image_layout_builder_unittest.cc',
        'pe_utils_unittest.cc',
        'pe_relinker_unittest.cc',
        'pe_relinker_util_unittest.cc',
        'pe_transform_policy_unittest.cc',
        'serialization_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'no_exports_dll',
        'pe_app_lib',
        'pe_lib',
        'pe_unittest_utils',
        'test_dll',
        'test_dll_obj',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/ar/ar.gyp:ar_unittest_utils',
        '<(src)/syzygy/assm/assm.gyp:assm_unittest_utils',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_unittest_lib',
        '<(src)/syzygy/block_graph/orderers/block_graph_orderers.gyp:'
            'block_graph_orderers_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/orderers/pe_orderers.gyp:pe_orderers_lib',
        '<(src)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_lib',
        '<(src)/syzygy/test_data/test_data.gyp:copy_test_dll',
        '<(src)/syzygy/test_data/test_data.gyp:copy_test_dll_compilands',
        '<(src)/syzygy/test_data/test_data.gyp:signed_test_dll',
        '<(src)/syzygy/testing/testing.gyp:testing_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'test_dll_no_private_symbols',
      'type': 'static_library',
      'sources': [
        'test_dll_no_private_symbols.cc',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'DebugInformationFormat': 0,  # No debug information.
        },
      },
    },
    {
      'target_name': 'test_dll',
      'type': 'loadable_module',
      'includes': ['../build/masm.gypi'],
      'sources': [
        'test_dll.cc',
        'test_dll.def',
        'test_dll.rc',
        'test_dll_label_test_func.asm',
      ],
      'dependencies': [
        'export_dll',
        'test_dll_no_private_symbols',
        '<(src)/syzygy/version/version.gyp:syzygy_version',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # We delay load ole32 purely to test delay load PE parsing.
          'DelayLoadDLLs': [
            'ole32.dll',
          ],
          'IgnoreDefaultLibraryNames': [
            'libcmtd.lib',
          ],
          # Force MSVS to produce the same output name as Ninja.
          'ImportLibrary': '$(OutDir)lib\$(TargetFileName).lib'
        },
      },
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
              # Ensure that the checksum present in the header of the binaries
              # is set.
              'SetChecksum': 'true',
            },
            'VCCLCompilerTool': {
              'BasicRuntimeChecks': '0',
              # Asan needs the application to be linked with the release static
              # runtime library. Otherwise, memory allocation functions are
              # wrapped and hide memory bugs like overflow/underflow.
              'RuntimeLibrary':  '0', # 0 = /MT (nondebug static)
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
      'target_name': 'test_dll_x64',
      'type': 'loadable_module',
      'sources': [
        'test_dll_x64.cc',
        'test_dll_x64.def',
        'test_dll_x64.rc',
      ],
      'dependencies': [
        'export_dll_x64',
        '<(src)/syzygy/version/version.gyp:syzygy_version',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # We delay load ole32 purely to test delay load PE parsing.
          'DelayLoadDLLs': [
            'ole32.dll',
          ],
          'IgnoreDefaultLibraryNames': [
            'libcmtd.lib',
          ],
        },
      },
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
              # Ensure that the checksum present in the header of the binaries
              # is set.
              'SetChecksum': 'true',
            },
            'VCCLCompilerTool': {
              'BasicRuntimeChecks': '0',
              # Asan needs the application to be linked with the release static
              # runtime library. Otherwise, memory allocation functions are
              # wrapped and hide memory bugs like overflow/underflow.
              'RuntimeLibrary':  '0', # 0 = /MT (nondebug static)
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
          'msvs_target_platform': 'x64',
          'msvs_configuration_platform': 'x64',
        },
      },
    },
    {
      # This target generates no_exports_dll.dll, which contains an empty export
      # data directory.
      'target_name': 'no_exports_dll',
      'type': 'loadable_module',
      'sources': [
        'no_exports_dll.cc',
        'no_exports_dll.def',
      ],
    },
    {
      # This target generates the test_dll object files in different
      # formats, for testing.
      'target_name': 'test_dll_obj',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'working_dir': '<(PRODUCT_DIR)/test_data',
      'actions': [
        {
          'action_name': 'compile_coff',
          'inputs': [
            'test_dll.cc',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/test_dll.coff_obj',
            '<(PRODUCT_DIR)/test_data/test_dll.coff_obj.pdb',
          ],
          'action': [
            'cl',
            '/c',
            '/Gy',  # Enable function-level linking.
            '/Zi',  # Enable debug information in COFF+PDB.
            '/Fo<(PRODUCT_DIR)\\test_data\\test_dll.coff_obj',
            '/Fd<(PRODUCT_DIR)\\test_data\\test_dll.coff_obj.pdb',
            'test_dll.cc',
          ],
          'dependencies': [
            'test_dll.cc',
          ],
        },
        {
          'action_name': 'compile_ltcg',
          'inputs': [
            'test_dll.cc',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/test_dll.ltcg_obj',
          ],
          'action': [
            'cl',
            '/c',
            '/GL',
            '/Fo<(PRODUCT_DIR)\\test_data\\test_dll.ltcg_obj',
            'test_dll.cc',
          ],
        },
      ],
    },
    {
      'target_name': 'export_dll',
      'type': 'shared_library',
      'sources': [
        'export_dll.cc',
        'export_dll.def',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Force MSVS to produce the same output name as Ninja.
          'ImportLibrary': '$(OutDir)lib\$(TargetFileName).lib'
        },
      },
    },
    {
      'target_name': 'export_dll_x64',
      'type': 'shared_library',
      'sources': [
        'export_dll.cc',
        'export_dll_x64.def',
      ],
      'msvs_settings': {
      },
      'configurations': {
        'Common_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              'VCLinkerTool': {
                # Force MSVS to produce the same output name as Ninja.
                'ImportLibrary': '$(OutDir)lib\$(TargetFileName).lib'
              },
            },
          },
          'msvs_target_platform': 'x64',
          'msvs_configuration_platform': 'x64',
        },
      },
    },
    {
      'target_name': 'decompose_image_to_text',
      'type': 'executable',
      'sources': [
        'decompose_image_to_text_main.cc',
      ],
      'dependencies': [
        'pe_app_lib',
        'pe_lib',
        '<(src)/base/base.gyp:base',
      ],
      'run_as': {
        'working_directory': '$(ConfigurationDir)',
        'action': [
          '$(TargetPath)',
          '--image=test_dll.dll',
          '--basic-blocks',
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
        'pe_app_lib',
        'pe_lib',
        '<(src)/base/base.gyp:base',
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
