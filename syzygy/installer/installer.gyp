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
    'candle_exe': '<(src)\\third_party\\wix\\files\\candle.exe',
    'light_exe': '<(src)\\third_party\\wix\\files\\light.exe',
  },
  'targets': [
    {
      'target_name': 'syzyprof',
      'type': 'none',
      'variables': {
        'binaries': [
          '<(src)/third_party/debugging_tools/files/DbgHelp.dll',
          '<(src)/third_party/debugging_tools/files/SymSrv.dll',
          '<(PRODUCT_DIR)/call_trace_service.exe',
          '<(PRODUCT_DIR)/instrument.exe',
          '<(PRODUCT_DIR)/instrument.exe.pdb',
          '<(PRODUCT_DIR)/grinder.exe',
          '<(PRODUCT_DIR)/grinder.exe.pdb',
          '<(PRODUCT_DIR)/profile_client.dll',
          '<(PRODUCT_DIR)/profile_client.dll.pdb',
        ],
        'sources': [
          'InstrumentChrome.bat',
          'license.rtf',
          'ReadMe.txt',
          'SyzyProf.bat',
          'syzyprof.wxs',
          'version.wxi.template',
        ],
      },
      'sources': [
        '<@(sources)',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/profiler/profiler.gyp:profile_client',
        '<(src)/syzygy/grinder/grinder.gyp:grinder',
        '<(src)/syzygy/instrument/instrument.gyp:instrument',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
      ],
      'msvs_cygwin_shell': 0,
      'actions': [
        {
          'action_name': 'make_version_wxi',
          'inputs': [
            '<(src)/syzygy/build/template_replace.py',
            '<(src)/syzygy/VERSION',
            'version.wxi.template',
          ],
          'outputs': [
            '<(INTERMEDIATE_DIR)/version.wxi',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/template_replace.py',
            '--input', 'version.wxi.template',
            '--output', '<(INTERMEDIATE_DIR)/version.wxi',
            '<(src)/syzygy/VERSION',
          ],
          'process_outputs_as_sources': 1,
        },
        {
          'action_name': 'candle',
          'inputs': [
            'syzyprof.wxs',
            '<(INTERMEDIATE_DIR)/version.wxi',
          ],
          'outputs': [
            '<(INTERMEDIATE_DIR)/syzyprof.wixobj',
          ],
          'action': [
            '<(candle_exe)',
            '-out',
            '<@(_outputs)',
            'syzyprof.wxs',
            '-dCALL_TRACE_SERVICE_EXE=<(PRODUCT_DIR)/call_trace_service.exe',
            '-dINSTRUMENT_EXE=<(PRODUCT_DIR)/instrument.exe',
            '-dINSTRUMENT_PDB=<(PRODUCT_DIR)/instrument.exe.pdb',
            '-dGRINDER_EXE=<(PRODUCT_DIR)/grinder.exe',
            '-dGRINDER_PDB=<(PRODUCT_DIR)/grinder.exe.pdb',
            '-dPROFILE_CLIENT_DLL=<(PRODUCT_DIR)/profile_client.dll',
            '-dPROFILE_CLIENT_PDB=<(PRODUCT_DIR)/profile_client.dll.pdb',
            '-dVERSION_WXI=<(INTERMEDIATE_DIR)/version.wxi',
          ],
          'process_outputs_as_sources': 1,
        },
        {
          'action_name': 'light',
          'extension': 'wxs',
          'inputs': [
            '<(INTERMEDIATE_DIR)/syzyprof.wixobj',
            '<@(binaries)',
            '<@(sources)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/syzyprof.msi',
          ],
          'action': [
            '<(light_exe)',
            '<(INTERMEDIATE_DIR)/syzyprof.wixobj',
            '-ext', 'WixUIExtension',
            '-ext', 'WixUtilExtension',
            '-out', '<@(_outputs)',
          ],
          'process_outputs_as_sources': 1,
        },
      ],
    },
  ],
}
