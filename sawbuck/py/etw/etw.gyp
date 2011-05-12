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
    'etw_sources': [
      'etw/__init__.py',
      'etw/consumer.py',
      'etw/controller.py',
      'etw/evntcons.py',
      'etw/evntrace.py',
      'etw/guiddef.py',
      'etw/provider.py',
      'etw/util.py',
      'etw/descriptors/__init__.py',
      'etw/descriptors/binary_buffer.py',
      'etw/descriptors/event.py',
      'etw/descriptors/field.py',
      'etw/descriptors/fileio.py',
      'etw/descriptors/image.py',
      'etw/descriptors/pagefault.py',
      'etw/descriptors/pagefault_xp.py',
      'etw/descriptors/process.py',
      'etw/descriptors/registry.py',
      'etw/descriptors/thread.py',
    ],
  },
  'targets': [
    {
      'target_name': 'etw',
      'type': 'none',
      'sources': [
        '<@(etw_sources)',
      ],
      'actions': [
        {
          'action_name': 'build_etw',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<@(etw_sources)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/ETW-0.6.5.0-py2.6.egg',
          ],
          'action': [
            '<(DEPTH)/third_party/setuptools/setup_env.bat &&'
              '<(DEPTH)/third_party/python_26/python',
            'setup.py',
            'bdist_egg',
            '--dist-dir=<(PRODUCT_DIR)',
            '--bdist-dir=<(PRODUCT_DIR)/temp/etw/',
          ],
        },
      ],
    },
  ],
}
