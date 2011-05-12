# Copyright 2011 Google Inc.
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
    'etw_db_sources': [
      'setup.py',
      'etw_db/file.py',
      'etw_db/module.py',
      'etw_db/process.py',
      'etw_db/__init__.py',
    ],
  },
  'targets': [
    {
      'target_name': 'etw_db',
      'type': 'none',
      'sources': [
        '<@(etw_db_sources)',
      ],
      'actions': [
        {
          'action_name': 'build_etw_db',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<@(etw_db_sources)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/ETW_Db-0.1-py2.6.egg',
          ],
          'action': [
            '<(DEPTH)/third_party/setuptools/setup_env.bat &&'
              '<(DEPTH)/third_party/python_26/python',
            'setup.py',
            'bdist_egg',
            '--dist-dir=<(PRODUCT_DIR)',
            '--bdist-dir=<(PRODUCT_DIR)/temp/etw_db/',
          ],
        },
      ],
    },
  ],
}
