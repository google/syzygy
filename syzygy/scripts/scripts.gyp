# Copyright 2009 Google Inc. All Rights Reserved.
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
  },
  'targets': [
    {
      # Add new unittests to this target as inputs.
      'target_name': 'all_scripts',
      'type': 'none',
      'dependencies': [
        'benchmark/benchmark.gyp:*',
        'graph/graph.gyp:*',
      ],
    },
    {
      # This target copies the setuptools egg to the output directory
      # for easier reference for archiving and such.
      'target_name': 'setuptools',
      'type': 'none',
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)',
          'files': [
            '<(src)/third_party/setuptools/setuptools-0.6c11-py2.6.egg',
          ]
        },
      ],
    },
  ]
}
