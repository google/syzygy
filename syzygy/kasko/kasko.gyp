# Copyright 2014 Google Inc. All Rights Reserved.
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
      'target_name': 'kasko_lib',
      'type': 'static_library',
      'sources': [
        'client.cc',
        'client.h',
        'kasko_export.h',
        'reporter.cc',
        'reporter.h'
      ],
      'dependencies': [
      ],
      'defines': [
        'KASKO_IMPLEMENTATION',
      ],
    },
    {
      'target_name': 'kasko',
      'type': 'loadable_module',
      'sources': [
        'kasko_dll.cc',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        'kasko_lib',
      ],
      'defines': [
        'KASKO_IMPLEMENTATION',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Link against the XP-constrained user32 import libraries for
          # kernel32 and user32 of the platform-SDK provided one to avoid
          # inadvertently taking dependencies on post-XP user32 exports.
          'IgnoreDefaultLibraryNames': [
            'user32.lib',
            'kernel32.lib',
          ],
          'AdditionalDependencies=': [
            # Custom import libs.
            'user32.winxp.lib',
            'kernel32.winxp.lib',

            # SDK import libs.
            'dbghelp.lib',
            'psapi.lib',
            'rpcrt4.lib',
          ],
          'AdditionalLibraryDirectories': [
            '<(src)/build/win/importlibs/x86',
            '<(src)/syzygy/build/importlibs/x86',
          ],
          # This module should delay load nothing.
          'DelayLoadDLLs=': [
          ],
          # Force MSVS to produce the same output name as Ninja.
          'ImportLibrary': '$(OutDir)lib\$(TargetFileName).lib'
        },
      },
    },
    {
      'target_name': 'kasko_unittests',
      'type': 'executable',
      'sources': [
        'kasko_unittests_main.cc',
      ],
      'dependencies': [
        'kasko_lib',
        'kasko',
        '<(src)/testing/gtest.gyp:gtest',
       ],
      # TODO(erikwright): Is this needed?
      'msvs_settings': {
        'VCLinkerTool': {
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
  ],
}
