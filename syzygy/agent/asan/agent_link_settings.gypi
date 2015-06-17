# Copyright 2014 Google Inc. All Rights Reserved.
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
# Settings common to ASAN agent DLLs.

{
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
      ],
      'AdditionalLibraryDirectories': [
        '<(src)/build/win/importlibs/x86',
        '<(src)/syzygy/build/importlibs/x86',
      ],
      # Force MSVS to produce the same output name as Ninja.
      'ImportLibrary': '$(OutDir)lib\$(TargetFileName).lib'
    },
  }
}
