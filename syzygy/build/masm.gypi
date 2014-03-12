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
#
# This include file defines a rule for assembling .asm files. Include
# it in any target that has one or more .asm sources.

{
  'rules': [
    {
      'rule_name': 'Assemble',
      'msvs_cygwin_shell': 0,
      'extension': 'asm',
      'inputs': [],
      'outputs': [
        '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
      ],
      'action': [
        'ml.exe',
          '/safeseh',
          '/Zi',
          '/Fo', '<(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj',
          '/c', '<(RULE_INPUT_PATH)',
      ],
      'process_outputs_as_sources': 1,
      'message': 'Assembling <(RULE_INPUT_PATH) to '
                 '<(INTERMEDIATE_DIR)\<(RULE_INPUT_ROOT).obj.',
    },
  ],
}
