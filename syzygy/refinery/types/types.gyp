# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
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
      'target_name': 'types_lib',
      'type': 'static_library',
      'sources': [
        'dia_crawler.cc',
        'dia_crawler.h',
        'pdb_crawler.cc',
        'pdb_crawler.h',
        'type.cc',
        'type.h',
        'type_namer.cc',
        'type_namer.h',
        'type_repository.cc',
        'type_repository.h',
        'typed_data.cc',
        'typed_data.h',
      ],
      'dependencies': [
        'test_typenames',
        'test_types',
        '<(src)/syzygy/pe/pe.gyp:dia_sdk',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/refinery/core/core.gyp:refinery_core_lib',
      ],
    },
    {
      'target_name': 'test_typenames',
      'type': 'loadable_module',
      'sources': [
        'test_typenames.def',
        'test_typenames_main.cc',
        'test_typenames.cc',
        'test_typenames.h',
      ],
      'dependencies': [
        'test_alias_lib',
      ],
      'conditions': [
        ['MSVS_VERSION=="2015"', {
          'configurations': {
            'Debug': {
              'msvs_settings': {
                'VCLinkerTool': {
                  'AdditionalDependencies': [
                    'libucrtd.lib'
                  ],
                },
              },
            },
            'Coverage': {
              'msvs_settings': {
                'VCLinkerTool': {
                  'AdditionalDependencies': [
                    'libucrtd.lib'
                  ],
                },
              },
            },
          },
        }],
      ],
      # Test data settings should match those of an official Chrome build.
      'msvs_settings': {
        'VCCLCompilerTool': {
          'EnableIntrinsicFunctions': 'true',
          'BufferSecurityCheck': 'false',
          'FavorSizeOrSpeed': '1',  # 1: favorSpeed
          'WholeProgramOptimization': 'true',
        },
        'VCLinkerTool': {
          'EntryPointSymbol': 'EntryPoint',
          'LinkTimeCodeGeneration': '1',
          'SetChecksum': 'true',
          # Turn down incremental linking for the test to avoid types
          # languishing from build to build.
          'LinkIncremental': '1',
        },
      },
    },
    {
      'target_name': 'test_types',
      'type': 'loadable_module',
      'sources': [
        'test_types.def',
        'test_types.h',
        'test_types_main.cc',
        'test_types_one.cc',
        'test_types_two.cc',
      ],
      'dependencies': [
        'test_alias_lib',
      ],
      'conditions': [
        ['MSVS_VERSION=="2015"', {
          'configurations': {
            'Release': {
              'msvs_settings': {
                'VCLinkerTool': {
                  'AdditionalDependencies': [
                    'vcruntime.lib'
                  ],
                },
              },
            },
            'Debug': {
              'msvs_settings': {
                'VCLinkerTool': {
                  'AdditionalDependencies': [
                    'libucrtd.lib'
                  ],
                },
              },
            },
            'Coverage': {
              'msvs_settings': {
                'VCLinkerTool': {
                  'AdditionalDependencies': [
                    'libucrtd.lib'
                  ],
                },
              },
            },
          },
        }],
      ],
      # Test data settings should match those of an official Chrome build.
      'msvs_settings': {
        'VCCLCompilerTool': {
          'EnableIntrinsicFunctions': 'true',
          'BufferSecurityCheck': 'false',
          'FavorSizeOrSpeed': '1',  # 1: favorSpeed
          'WholeProgramOptimization': 'true',
        },
        'VCLinkerTool': {
          'EntryPointSymbol': 'EntryPoint',
          'LinkTimeCodeGeneration': '1',
          'SetChecksum': 'true',
          # Turn down incremental linking for the test to avoid types
          # languishing from build to build.
          'LinkIncremental': '1',
        },
      },
    },
    {
      'target_name': 'test_vtables',
      'type': 'loadable_module',
      'sources': [
        'test_vtables.def',
        'test_vtables.cc',
      ],
      'dependencies': [
        'test_alias_lib',
      ],
      # Test data settings should match those of an official Chrome build.
      'msvs_settings': {
        'VCCLCompilerTool': {
          'EnableIntrinsicFunctions': 'true',
          'BufferSecurityCheck': 'false',
          'FavorSizeOrSpeed': '1',  # 1: favorSpeed
          'WholeProgramOptimization': 'true',
        },
        'VCLinkerTool': {
          'LinkTimeCodeGeneration': '1',
          'SetChecksum': 'true',
          # Turn down incremental linking for the test to avoid types
          # languishing from build to build.
          'LinkIncremental': '1',
        },
      },
    },
    {
      'target_name': 'test_alias_lib',
      'type': 'static_library',
      'sources': [
        'alias.cc',
        'alias.h',
      ],
      # Test data settings should match those of an official Chrome build. Note
      # however that in the the case of the alias library, we disable whole
      # program optimization.
      'msvs_settings': {
        'VCCLCompilerTool': {
          'EnableIntrinsicFunctions': 'true',
          'BufferSecurityCheck': 'false',
          'FavorSizeOrSpeed': '1',  # 1: favorSpeed
          # Override the inherited setting for WholeProgramOptimization in order
          # to disable it. This should defeat any attempt to defeat aliasing.
          # We manually disable it, as the gyp 'WholeProgramOptimization'
          # setting does not seem to have a disabled value.
          'AdditionalOptions': [
            '/GL-'
          ]
        },
        'VCLinkerTool': {
          'LinkTimeCodeGeneration': '1',
          'SetChecksum': 'true',
          # Turn down incremental linking for the test to avoid types
          # languishing from build to build.
          'LinkIncremental': '1',
        },
      },
    },
    {
      'target_name': 'types_unittest_utils',
      'type': 'static_library',
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_unittest_utils',
        '<(src)/syzygy/refinery/core/core.gyp:refinery_core_lib',
        '<(src)/testing/gtest.gyp:gtest',
      ],
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
    },
  ],
}
