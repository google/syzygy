# Copyright 2009 Google Inc.
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
    'benchmark_sources': [
      'benchmark.py',
      'bootstrap.py',
      'chrome_control.py',
      'chrome_control_test.py',
      'ez_setup.py',
      'setup.py',
    ],
  },
  'targets': [
    {
      'target_name': 'benchmark',
      'type': 'none',
      'sources': [
        '<@(benchmark_sources)',
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/snapshot/snapshot.gyp:run_in_snapshot',
        '<(DEPTH)/syzygy/snapshot/snapshot.gyp:run_in_snapshot_xp',
        '<(DEPTH)/syzygy/snapshot/snapshot.gyp:run_in_snapshot_x64',
      ],
      'actions': [
        {
          'action_name': 'build_benchmark',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<@(benchmark_sources)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/Benchmark_Chrome-0.1dev-py2.6.egg',
          ],
          'action': [
            '<(DEPTH)/third_party/setuptools/setup_env.bat &&'
              '<(DEPTH)/third_party/python_26/python',
            'setup.py',
            'bdist_egg',
            '--exe-dir=<(PRODUCT_DIR)',
            '--dist-dir=<(PRODUCT_DIR)',
            '--bdist-dir=<(PRODUCT_DIR)/temp/benchmark/',
          ],
        },
      ],
    },
    {
      'target_name': 'benchmark_zip',
      'type': 'none',
      'dependencies': [
        'benchmark',
        '<(DEPTH)/sawbuck/py/etw/etw.gyp:etw',
        '<(DEPTH)/syzygy/py/etw_db/etw_db.gyp:etw_db',
        '<(DEPTH)/syzygy/scripts/scripts.gyp:setuptools',
      ],
      'copies': [
        {
          # We copy the benchmark script to the output directory to
          # stage everything from a single directory.
          'destination': '<(PRODUCT_DIR)',
          'files': [
            'benchmark.bat',
          ]
        },
      ],
      'actions': [
        {
          'action_name': 'create_benchmark_zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(PRODUCT_DIR)/benchmark.bat',
            '<(PRODUCT_DIR)/Benchmark_Chrome-0.1dev-py2.6.egg',
            '<(PRODUCT_DIR)/ETW-0.6.5.0-py2.6.egg',
            '<(PRODUCT_DIR)/ETW_Db-0.1-py2.6.egg',
            '<(PRODUCT_DIR)/setuptools-0.6c11-py2.6.egg',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/benchmark.zip',
          ],
          'action': [
            '<(DEPTH)/third_party/python_26/python',
            '<(DEPTH)/syzygy/tools/flat_zip.py',
            '<@(_outputs)',
            '<@(_inputs)',
          ],
        },
      ],
    },
  ]
}
