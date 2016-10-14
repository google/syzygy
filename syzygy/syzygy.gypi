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
    'python_exe': '<(DEPTH)/syzygy/build/python26.bat',

    # This allows us to decouple the repository root from '<(DEPTH)', as
    # the relative depth of a pure git repository and an SVN repository
    # is different.
    'src': '<(DEPTH)',

    # Remove the base/build dependency on the existence of a chrome/VERSION
    # file.
    'test_isolation_mode': 'noop',

    'output_dir_prefix': 'out',

    'msvs_xtree_patched%': '0',

    # The current PGO phase. 0 means that the PGO is disabled, 1 should be used
    # for the instrumentation phase and 2 is for the optimization one. The
    # targets are responsible on setting the appropriate linker settings
    # depending on the value of this flag.
    'pgo_phase%': '0',

    # Use the handle verifier in a single module mode so we can use some HANDLE
    # during the initialization of our agents.
    'single_module_mode_handle_verifier': '1',
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
        # Disable various noisy warnings that have low value.
        'AdditionalOptions': [
          '/wd4201',  # nameless struct/union
        ],
      },
      'VCLinkerTool': {
        # Indicate that debug information is being generated. This is necessary
        # to coax Ninja into indicating that PDBs have been generated as part
        # of a linker step.
        'GenerateDebugInformation': 'true',
        # Enable support for large address spaces.
        'LargeAddressAware': 2,
        # Default to using more sane PDB filenames. Otherwise, both foo.exe and
        # foo.dll will generate foo.pdb. This ensures that instead we see
        # foo.exe.pdb and foo.dll.pdb.
        'ProgramDatabaseFile': '$(TargetPath).pdb',
        # common.gypi overrides VCLinkerTool::LargeAddressAware via an
        # addition option. We unset this so that we can control our own
        # settings.
        'AdditionalOptions!': [ '/largeaddressaware' ],
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
          'BUILD_OUTPUT_DIR="<(output_dir_prefix)/Coverage"',
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
          'BUILD_OUTPUT_DIR="<(output_dir_prefix)/Release"',
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
              'VCLibrarianTool': {
                'LinkTimeCodeGeneration': 'true',  # /LTCG
              },
              'VCLinkerTool': {
                # 0: Inherit, 1: Enabled, 2-4: For PGO.
                'conditions': [
                  ['pgo_phase==0', {
                    'LinkTimeCodeGeneration': '1',
                  }],
                ],
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
          'BUILD_OUTPUT_DIR="<(output_dir_prefix)/Debug"',
         ],
      },
      'Debug_x64': {
        'defines': [
          'BUILD_OUTPUT_DIR="<(output_dir_prefix)/Debug_x64"',
         ],
      },
      'Release_x64': {
        'defines': [
          'BUILD_OUTPUT_DIR="<(output_dir_prefix)/Release_x64"',
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
