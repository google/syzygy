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
    # All files that should be archived after a successful official build are
    # named here.
    'files_to_archive': [
      '<(PRODUCT_DIR)/benchmark.zip',
      '<(PRODUCT_DIR)/binaries.zip',
      '<(PRODUCT_DIR)/lib.zip',
      '<(PRODUCT_DIR)/symbols.zip',
      '<(PRODUCT_DIR)/syzyprof.msi',
      # TODO(sebmarchand): Put back the includes archive once we have some
      #     header files to publish.
    ],
  },
  'includes': [
    'binaries.gypi',
  ],
  'targets': [
    {
      'target_name': 'official_build',
      'type': 'none',
      'dependencies': [
        'archive_build_artifacts',
      ],
    },
    {
      'target_name': 'archive_build_artifacts',
      'type': 'none',
      'dependencies': [
        '<(src)/syzygy/syzygy.gyp:build_all',
        'binaries_zip',
      ],
      'copies': [{
        'destination': '<(PRODUCT_DIR)/archive',
        'files': ['<@(files_to_archive)'],
      }],
    },
    {
      'target_name': 'binaries_zip',
      'type': 'none',
      'dependencies': [
        'readme_txt',
        '<(src)/syzygy/syzygy.gyp:build_all',
      ],
      'actions': [
        {
          'action_name': 'create_binaries_zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            'create_zip.py',
            'FILTER-FORMAT.TXT',
            'FILTER-SAMPLE.JSON',
            'FILTER-SAMPLE.TXT',
            'LICENSE.TXT',
            'PEHACKER.TXT',
            'RELEASE-NOTES.TXT',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
            '<@(binaries)',
            '<@(experimental_binaries)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/binaries.zip',
          ],
          'action': [
            '<(python_exe)',
            'create_zip.py',
            '--output',
            '<(PRODUCT_DIR)/binaries.zip',
            '--files',
            'FILTER-FORMAT.TXT',
            'FILTER-SAMPLE.JSON',
            'FILTER-SAMPLE.TXT',
            'LICENSE.TXT',
            'PEHACKER.TXT',
            'RELEASE-NOTES.TXT',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
            '<@(binaries)',
            '--subdir',
            'experimental',
            '<@(experimental_binaries)',
          ],
        },
        {
          'action_name': 'create_symbols_zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            'create_zip.py',
            '<@(symbols)',
            '<@(experimental_symbols)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/symbols.zip',
          ],
          'action': [
            '<(python_exe)',
            'create_zip.py',
            '--output',
            '<(PRODUCT_DIR)/symbols.zip',
            '--files',
            '<@(symbols)',
            '--subdir',
            'experimental',
            '<@(experimental_symbols)',
          ],
        },
        {
          'action_name': 'create_lib_zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            'create_zip.py',
            '<(lib_dir)/syzyasan_rtl.dll.lib',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/lib.zip',
          ],
          'action': [
            '<(python_exe)',
            'create_zip.py',
            '--output',
            '<(PRODUCT_DIR)/lib.zip',
            '--files',
            '<(lib_dir)/syzyasan_rtl.dll.lib',
          ],
        },
      ],
    },
    {
      'target_name': 'readme_txt',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'README.TXT.template',
      ],
      'actions': [
        # Generate the README.TXT file from its template.
        {
          'action_name': 'make_readme_txt',
          'inputs': [
            '<(src)/syzygy/build/LASTCHANGE.gen',
            '<(src)/syzygy/build/README.TXT.template',
            '<(src)/syzygy/build/TIMESTAMP.gen',
            '<(src)/syzygy/build/template_replace.py',
            '<(src)/syzygy/SYZYGY_VERSION',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/template_replace.py',
            '--input',
            '<(src)/syzygy/build/README.TXT.template',
            '--output',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
            '<(src)/syzygy/SYZYGY_VERSION',
            '<(src)/syzygy/build/LASTCHANGE.gen',
            '<(src)/syzygy/build/TIMESTAMP.gen',
          ],
          'process_outputs_as_sources': 1,
        },
      ],
    },
  ],
}
