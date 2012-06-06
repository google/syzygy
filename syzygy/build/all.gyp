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
    # All files that should be archived after a
    # successful build are named here.
    'files_to_archive': [
      '<(PRODUCT_DIR)/benchmark.zip',
      '<(PRODUCT_DIR)/syzyprof.msi',
    ],
  },
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
      ],
      'copies': [{
        'destination': '<(PRODUCT_DIR)/archive',
        'files': ['<@(files_to_archive)'],
      }],
    },
  ],
}
