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
#
# This include file will be in force for all gyp files processed in the
# Syzygy tree.

{
  'variables': {
    # By default we are not producing an official build.
    'official_build%': 0,

    # Make sure we use the bundled version of python rather than any others
    # installed on the system,
    'python_exe': '<(DEPTH)/third_party/python_26/python.exe',

    # This allows us to decouple the repository root from '<(DEPTH)', as
    # the relative depth of a pure git repository and an SVN repository
    # is different.
    'src': '<(DEPTH)',

    'conditions': [
      ['"<(GENERATOR)"=="ninja" or "<(GENERATOR)"=="msvs-ninja"', {
        'output_dir_prefix': 'out',
      }],
      ['"<(GENERATOR)"=="msvs"', {
        'output_dir_prefix': 'build',
      }],
    ],
  },
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
    'msvs_settings': {
      'VCCLCompilerTool': {
        # See http://msdn.microsoft.com/en-us/library/aa652260(v=vs.71).aspx
        # Equivalent to debugEnabled, which is equivalent to /Zi.
        'DebugInformationFormat': 3,
      },
      'VCLinkerTool': {
        # Enable support for large address spaces.
        'LargeAddressAware': 2,
      },
    },
    'configurations': {
      # A coverage build is for all intents and purposes a debug build with
      # profile information (and therefore no incremental linking). This allows
      # it to be instrumented.
      'Coverage_Base': {
        'abstract': 1,
        'inherit_from': ['Debug_Base'],
        'defines': [
          # This global define is in addition to _DEBUG.
          '_COVERAGE_BUILD',
          '_BUILD_OUTPUT_DIR="<(output_dir_prefix)/Coverage"',
          # Turn off iterator debugging for coverage, as it slows down
          # all iterator-related operations without improving coverage.
          '_HAS_ITERATOR_DEBUGGING=0',
        ],
        'msvs_settings': {
          'VCCLCompilerTool': {
          },
          'VCLinkerTool': {
            # 0: inherit, 1: disabled, 2: enabled.
            'LinkIncremental': '1',
            # This corresponds to the /PROFILE flag, which enables the
            # resulting binaries to be instrumented by vsinstr.exe.
            'Profile': 'true',
            # Ensure that the checksum present in the header of the binaries is
            # set.
            'SetChecksum': 'true',
          },
        },
      },
      'Release': {
        'defines': [
          '_BUILD_OUTPUT_DIR="<(output_dir_prefix)/Release"',
        ],
        'conditions': [
          # We up the level of optimizations for official builds.
          ['OS=="win" and official_build==1', {
            'defines': [
              # We set this define to avoid the DCHECKs to generate any code in
              # an official build.
              'OFFICIAL_BUILD',
            ],
            'msvs_settings': {
              'VCCLCompilerTool': {
                'EnableIntrinsicFunctions': 'true',
                'BufferSecurityCheck': 'false',
                # 0: favorNone, 1: favorSpeed, 2: favorSize.
                'FavorSizeOrSpeed': '1',
                'WholeProgramOptimization': 'true',
              },
              'VCLinkerTool': {
                # 0: Inherit, 1: Enabled, 2-4: For PGO.
                'LinkTimeCodeGeneration': '1',
                # Ensure that the checksum present in the header of the binaries
                # is set.
                'SetChecksum': 'true',
              },
            },
          }],
        ],
      },
      'Coverage': {
        'inherit_from': ['Common_Base', 'x86_Base', 'Coverage_Base'],
      },
      'Debug': {
        'defines': [
          '_BUILD_OUTPUT_DIR="<(output_dir_prefix)/Debug"',
         ],
      },
      'conditions': [
        ['OS=="win"', {
          'Coverage_x64': {
            'inherit_from': ['Common_Base', 'x64_Base', 'Coverage_Base'],
          },
        }],
      ],
    },
  },
}
