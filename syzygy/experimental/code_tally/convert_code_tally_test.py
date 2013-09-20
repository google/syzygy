#!/usr/bin/python2.7
#
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

import json
import os
import StringIO
import subprocess
import sys
import tempfile
import unittest

import convert_code_tally

# A basic set of input data for the tests.
INPUT_JSON = {
        'executable': {'name': 'chrome.dll'},
        'sources': ['c:\\file', "c:\\folder\\FILE2", "C:\\FOLDER\\file3"],
        'objects': {"file.obj": {
                        "namespace::function": {
                            "size": 100.0,
                            "contribs": [0, [1, 5.0], 1, [5, 95.0]]}},
                    "file2.obj": {
                        "namespace::default": {"size": 100},
                        "namespace::helper": {
                            "size": 30.0,
                            "contribs": [0, [2, 1.0, 3, 1.0],
                                         1, [1, 8.0, 4, 12.0],
                                         2, [15, 8.0]]}}}}


class ConvertCodeTallyTest(unittest.TestCase):
  def test_load_input_json(self):
    input_data = {'executable': {'name': 'chrome.dll'},
                  'sources': ['c:\\file', 'C:\\FILE_2']}

    initialized_data = convert_code_tally._normalize_paths(input_data)

    # Ensure that all paths are lower case.
    self.assertEqual(['c:\\file', 'c:\\file_2'], initialized_data['sources'])

  def check_entity(self, entity, parent, size, is_directory):
    self.assertEqual(parent, entity.parent)
    self.assertAlmostEqual(size, entity.size)
    self.assertEqual(is_directory, entity.is_directory)

  def test_generate_entities_simple(self):
    input_data = {
        'executable': {'name': 'chrome.dll'},
        'sources': ['c:\\file'],
        'objects': {"file.obj": {"namespace::function": {
            "size": 5.0,
            "contribs": [0, [1, 5.0]]}}}}

    entities = convert_code_tally._generate_entities(input_data)

    self.assertEqual(2, len(entities))
    for entity in entities:
      if entity.name == 'c:':
        self.check_entity(entity, '', 5.0, True)
      elif entity.name == 'file':
        self.check_entity(entity, 'c:', 5.0, False)
      else:
        self.fail('Unknown entity, %s' % str(entity))

  def test_calculate_sizes(self):
    sizes = convert_code_tally._calculate_sizes(INPUT_JSON)

    self.assertEqual(3, len(sizes))
    self.assertAlmostEqual(7.0, sizes[0])
    self.assertAlmostEqual(115.0, sizes[1])
    self.assertAlmostEqual(8.0, sizes[2])

  def test_generate_source_tree(self):
    input_json = convert_code_tally._normalize_paths(INPUT_JSON)
    sizes = convert_code_tally._calculate_sizes(input_json)

    source_tree = convert_code_tally._generate_source_tree(
        INPUT_JSON['sources'], sizes)

    expected_tree = {'c:': {'file': 7.0,
                            'folder': {'file2': 115.0, 'file3': 8.0}}}

    self.assertEqual(expected_tree, source_tree)

  def test_generate_entities_complex(self):
    entities = convert_code_tally._generate_entities(INPUT_JSON)

    self.assertEqual(5, len(entities))

    for entity in entities:
      if entity.name == 'c:':
        self.check_entity(entity, '', 130.0, True)
      elif entity.name == 'file':
        self.check_entity(entity, 'c:', 7.0, False)
      elif entity.name == 'folder':
        self.check_entity(entity, 'c:', 123.0, True)
      elif entity.name == 'file2':
        self.check_entity(entity, 'c:\\folder', 115.0, False)
      elif entity.name == 'file3':
        self.check_entity(entity, 'c:\\folder', 8.0, False)
      else:
        self.fail('Unknown entity, %s' % str(entity))

  def check_entity_dump(self, entity, parent, size, is_directory):
    self.assertEqual(parent, entity['parent'])
    self.assertAlmostEqual(size, entity['size'])
    self.assertEqual(is_directory, entity['is_directory'])

  def test_output_converted_json(self):
    entities = convert_code_tally._generate_entities(INPUT_JSON)


    class Options(object):
      def __init__(self):
        self.master_id = 'master_bot'
        self.builder_name = 'builder_3'
        self.build_number = '12345'
        self.revision = '123'

    options = Options()
    name = 'chrome.dll'

    output_file = StringIO.StringIO()
    convert_code_tally._output_converted_json(
        output_file, options, name, entities)

    output_json = json.loads(output_file.getvalue())

    self.assertEqual(options.master_id, output_json['master.id'])
    self.assertEqual(options.builder_name, output_json['buildername'])
    self.assertEqual(options.build_number, output_json['buildnumber'])
    self.assertEqual(options.revision, output_json['revision'])

    self.assertEqual(name, output_json['name'])

    entities = output_json['entities']
    self.assertEqual(5, len(entities))

    for entity in entities:
      if entity['name'] == 'c:':
        self.check_entity_dump(entity, '', 130.0, True)
      elif entity['name'] == 'file':
        self.check_entity_dump(entity, 'c:', 7.0, False)
      elif entity['name'] == 'folder':
        self.check_entity_dump(entity, 'c:', 123.0, True)
      elif entity['name'] == 'file2':
        self.check_entity_dump(entity, 'c:\\folder', 115.0, False)
      elif entity['name'] == 'file3':
        self.check_entity_dump(entity, 'c:\\folder', 8.0, False)
      else:
        self.fail('Unknown entity, %s' % str(entity))

  def test_end_to_end(self):
    """Just check that the script can be called without any problems."""
    try:
      input_file = tempfile.NamedTemporaryFile(delete=False)
      json.dump(INPUT_JSON, input_file)
      input_file.close()

      output_file = tempfile.NamedTemporaryFile()

      subprocess.check_call([sys.executable, 'convert_code_tally.py',
                             input_file.name, output_file.name])
    finally:
      if os.path.exists(input_file.name):
        os.remove(input_file.name)


if __name__ == '__main__':
    unittest.main()
