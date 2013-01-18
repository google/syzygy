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
    # All files that should be archived after a
    # successful build are named here.
    'files_to_archive': [
      '<(PRODUCT_DIR)/benchmark.zip',
      '<(PRODUCT_DIR)/syzyprof.msi',
      '<(PRODUCT_DIR)/binaries.zip',
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
        '<(DEPTH)/syzygy/syzygy.gyp:build_all',
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
        '<(DEPTH)/syzygy/syzygy.gyp:build_all',
      ],
      'actions': [
        {
          'action_name': 'create_binaries_zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            'create_zip.py',
            'LICENSE.TXT',
            'RELEASE-NOTES.TXT',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
            '<@(binaries)',
            '<@(experimental_binaries)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/binaries.zip',
          ],
          'action': [
            'python',
            'create_zip.py',
            '--output',
            '<(PRODUCT_DIR)/binaries.zip',
            '--files',
            'LICENSE.TXT',
            'RELEASE-NOTES.TXT',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
            '<@(binaries)',
            '--subdir',
            'experimental',
            '<@(experimental_binaries)',
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
      'dependencies': [
        # This generates the lastchange.gen file.
        '<(DEPTH)/syzygy/common/common.gyp:syzygy_version',
      ],
      'actions': [
        # Generate the timestamp.gen file.
        {
          'action_name': 'make_date_gen',
          'inputs': [
            'timestamp.py',
          ],
          'outputs': [
            # We include a fake output target to ensure this always runs
            # for every single build.
            'THIS_OUTPUT_IS_NEVER_GENERATED',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/timestamp.gen',
          ],
          'action': [
            'python',
            'timestamp.py',
            '--output',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/timestamp.gen',
          ],
        },
        # Generate the README.TXT file from its template.
        {
          'action_name': 'make_readme_txt',
          'inputs': [
            '<(DEPTH)/sawbuck/tools/template_replace.py',
            '<(DEPTH)/syzygy/build/README.TXT.template',
            '<(DEPTH)/syzygy/VERSION',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/timestamp.gen',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
          ],
          'action': [
            'python',
            '<(DEPTH)/sawbuck/tools/template_replace.py',
            '--input',
            '<(DEPTH)/syzygy/build/README.TXT.template',
            '--output',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/README.TXT',
            '<(DEPTH)/syzygy/VERSION',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/build/timestamp.gen',
          ],
          'process_outputs_as_sources': 1,
        },
      ],
    },
  ],
}
