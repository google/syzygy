# Copyright 2013 Google Inc. All Rights Reserved.
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
    'source_files': [
      'files/application.css',
      'files/favicon.ico',
      'files/favicon.png',
      'files/htmlrunner.js',
      'files/ie.css',
      'files/index.html',
      'files/jquery.js',
      'files/json.js',
      'files/JSON.php',
      'files/LICENSE',
      'files/pngfix.js',
      'files/README.chromium',
      'files/reset.css',
      'files/store.php',
      'files/test-head.html',
      'files/test-head.js',
      'files/test-tail.html',
      'files/test-tail.js',
      'files/web-style.css',
      'files/webrunner.js',
    ],
    'source_folders': [
      'files/images',
      'files/lib',
      'files/tests',
    ],
  },
  'targets': [
    {
      'target_name': 'dromaeo_zip',
      'type': 'none',
      'sources': [
        '<@(source_files)',
      ],
      'outputs': [
        '<(PRODUCT_DIR)/dromaeo.zip',
      ],
      'actions': [
        {
          'action_name': 'zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<@(source_files)',
            '<@(source_folders)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/dromaeo.zip',
          ],
          'action': [
            '<(python_exe)',
            '-m', 'zipfile',
            '-c', '<(PRODUCT_DIR)/dromaeo.zip',
            '<@(source_files)',
            '<@(source_folders)',
          ],
        },
      ],
    },
  ]
}
