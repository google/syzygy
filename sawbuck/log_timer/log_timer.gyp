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
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
      '../..',
    ],
  },
  'targets': [
    {
      'target_name': 'log_timer',
      'type': 'executable',
      'sources': [
        'log_timer.cc',
        'log_timer.h',
        'log_timer_main.cc',
      ],
      'dependencies': [
        '../log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/pcre/pcre.gyp:pcre_lib',
      ],
      'libraries': [
        'tdh.lib',
      ],
    },
  ]
}
