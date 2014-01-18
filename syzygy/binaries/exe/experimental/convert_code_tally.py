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
#
# Convert a code_tally.exe json file to a json file that can be uploaded to
# the app engine size server.


import json
import optparse
import os
import sys


def _json_default(obj):
  """Handles JSON serializablity of Entity class."""
  if isinstance(obj, Entity):
    return obj.__dict__
  raise TypeError(repr(obj) + ' is not JSON serializable')


class Entity(object):
  """An entity is a unit representing a single source file or folder that
  contributed to the dll.
  """

  def __init__(self, parent, name, size, is_directory=False):
    self.parent = parent
    self.name = name
    self.size = size
    self.is_directory = is_directory


def _normalize_paths(input_json):
  """Ensure that all paths are lower case (to prevent potential mis-matches,
  since Windows is case-insensitive.
  """
  normalized_json = input_json.copy()
  for i in range(len(normalized_json['sources'])):
    normalized_json['sources'][i] = normalized_json['sources'][i].lower()

  return normalized_json


def _calculate_sizes(input_json):
  """Calculate the sizes of all the source files, returning a list of floats
  representing the size in the same order as input_json['sources'].
  """
  source_sizes = [0.0] * len(input_json['sources'])

  for obj_name, value in input_json['objects'].iteritems():
    for func_name, func_prop in value.iteritems():
      # Even if we have the size property, without the contribs we are unable
      # to properly assign the sizes.
      if 'contribs' not in func_prop:
        continue

      contribs = func_prop['contribs']
      # The contribs value is a list where all the even elements are the source
      # file number, and the odd elements are the contributions for that file
      # (of the form [line position, size, line position, size, etc...]).
      contributors = contribs[::2]
      sizes = contribs[1::2]
      for contributor, size in zip(contributors, sizes):
        # TODO: include the line positions in the converted data.
        line_positions = size[::2]
        line_contributions = size[1::2]

        source_sizes[contributor] += sum(line_contributions)

  return source_sizes


def _generate_source_tree(sources, sizes):
  """Generates a dict equivalent to the source tree. Each element is either a
  file (so its value is its size) or a folder (so its value is a dictionary of
  all the files or folders found inside it).

  |sources| is a list of files to build the source tree out of, and |sizes|
  has the size for every file in |sources|.

  An example of a dict that might get returned:
  {
    'c': {
        'file1': 18.0,
        'folder': {'file2': 20}
         }
  }
  """
  source_tree = {}
  for filepath, size in zip(sources, sizes):
    split_path = filepath.split('\\')

    # Ensure that all the parent folders have been created.
    parent = source_tree
    for section in split_path[:-1]:
      parent = parent.setdefault(section, {})

    # Set the appropriate size for the file.
    parent[split_path[-1]] = size

  return source_tree


def _convert_subtree_to_entities(source_tree, parent):
  """Given a |source_tree| dictionary representing files and folders, rooted at
  |parent|, return the list of entities that contains all the tree's elements.

  An example of the |source_tree| input is:
  {
    'c': {
        'file1': 18.0,
        'folder': {'file2': 20}
         }
  }
  """
  entities = []
  for key, value in source_tree.iteritems():
    if isinstance(value, float):
      # A basic file entity.
      entities.append(Entity(parent, name=key, size=value))
    else:
      new_parent = key if not parent else parent + '\\' + key
      children = _convert_subtree_to_entities(value, new_parent)

      # Find the size of this directory, based on the sizes of it children.
      # Ignore any children's children, since they are already included in
      # their parent's sum.
      total_size = sum([child.size for child in children
                        if child.parent == new_parent])

      entities.extend(children)
      entities.append(
          Entity(parent, name=key, size=total_size, is_directory=True))

  return entities


def _generate_entities(input_json):
  """Convert the given input json data to a list of entities."""
  normalized_json = _normalize_paths(input_json)

  sizes = _calculate_sizes(normalized_json)
  source_tree = _generate_source_tree(normalized_json['sources'], sizes)

  return _convert_subtree_to_entities(source_tree, '')


def _output_converted_json(output_file, options, name, entities):
  """Store the list of entities in the given output file, also including the
  appropriate general fields (such as builder name, builder number, etc).
  """
  output_json = {
      'master.id': options.master_id,
      'buildername': options.builder_name,
      'buildnumber': options.build_number,
      'name': name,
      'revision': options.revision,
      'entities': entities,
      }

  print 'Saving converted file \'%s\'' % output_file
  json.dump(output_json, output_file, indent=2, default=_json_default)


def main():
  usage = "usage: %prog [options] input_code_tally_file output_json_file"
  parser = optparse.OptionParser(usage=usage)
  parser.add_option('--master_id', default='master',
                    help='The master of the machine that generated the code '
                         'tally.')
  parser.add_option('--builder_name', default='builder',
                    help='The name of the builder that generated the code '
                    'tally.')
  parser.add_option('--build_number', default='1',
                    help='The build number.')
  parser.add_option('--revision', default='1',
                    help='The revision of the code this code tally refers to.')
  (options, args) = parser.parse_args()

  if len(args) != 2:
    parser.error('Please list the input and output files.')

  input_file = args[0]
  output_file = args[1]

  if not os.path.exists(input_file):
    parser.error('The given input file, \'%s\', doesn\'t exist' % input_file)

  with open(input_file, 'r') as f:
    input_data = json.load(f)

  entities = _generate_entities(input_data)

  with open(output_file, 'w') as f:
    _output_converted_json(f,
                           options,
                           input_data['executable']['name'],
                           entities)


if __name__ == '__main__':
  sys.exit(main())
