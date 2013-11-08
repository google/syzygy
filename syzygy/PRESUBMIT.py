#!python
# Copyright 2012 Google Inc. All Rights Reserved.
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
# Presubmit script for Syzygy.

import itertools
import os
import re
import sys


# Determine the root of the source tree. We use getcwd() instead of __file__
# because gcl loads this script as text and runs it using eval(). In this
# context the variable __file__ is undefined. However, gcl assures us that
# the current working directory will be the directory containing this file.
SYZYGY_ROOT_DIR = os.path.abspath(os.getcwd())


# Bring in some presubmit tools.
sys.path.insert(0, os.path.join(SYZYGY_ROOT_DIR, 'py'))
import test_utils.presubmit as presubmit  # pylint: disable=F0401


# Bring in internal-only presubmit checks. These live in a parallel
# repository that is overlaid with the public version of syzygy. The
# internal presubmit check is expected to live in the 'internal'
# subdirectory off the syzygy root.
try:
  internal_dir = os.path.join(SYZYGY_ROOT_DIR, 'internal')
  if os.path.isdir(internal_dir):
    sys.path.insert(0, internal_dir)
  import internal_presubmit  # pylint: disable=F0401
except ImportError:
  internal_presubmit = None


_UNITTEST_MESSAGE = """\
Your %%s unittests must succeed before submitting! To clear this error,
  run: %s""" % os.path.join(SYZYGY_ROOT_DIR, 'run_all_tests.bat')


# License header and copyright line taken from:
# http://go/ossreleasing#Apache_License
_LICENSE_HEADER = """\
(#!python\n\
)?.*? Copyright 20[0-9][0-9] Google Inc\. All Rights Reserved\.\n\
.*?\n\
.*? Licensed under the Apache License, Version 2\.0 \(the "License"\);\n\
.*? you may not use this file except in compliance with the License\.\n\
.*? You may obtain a copy of the License at\n\
.*?\n\
.*?     http://www\.apache\.org/licenses/LICENSE-2\.0\n\
.*?
.*? Unless required by applicable law or agreed to in writing, software\n\
.*? distributed under the License is distributed on an "AS IS" BASIS,\n\
.*? WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.\n\
.*? See the License for the specific language governing permissions and\n\
.*? limitations under the License\.\n\
"""


# Regular expressions to recognize source and header files.
# These are lifted from presubmit_support.py in depot_tools and are
# formulated as a list of regex strings so that they can be passed to
# input_api.FilterSourceFile() as the white_list parameter.
_CC_SOURCES = (r'.+\.c$', r'.+\.cc$', r'.+\.cpp$', r'.+\.rc$')
_CC_HEADERS = (r'.+\.h$', r'.+\.inl$', r'.+\.hxx$', r'.+\.hpp$')
_CC_FILES = _CC_SOURCES + _CC_HEADERS
_CC_SOURCES_RE = re.compile('|'.join('(?:%s)' % x for x in _CC_SOURCES))

# Ignore the headers present in the binaries directory, as they're a copy of
# another header, making the header guard invalid.
_CC_FILES_BLACKLIST = [r'syzygy\\binaries\\.+\.h$']

# Regular expressions used to extract headers and recognize empty lines.
_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+(?P<header>[<"][^<"]+[>"])'
                         r'\s*(?://.*(?P<nolint>NOLINT).*)?$')
_COMMENT_OR_BLANK_RE = re.compile(r'^\s*(?://.)?$')


def _IsSourceHeaderPair(source_path, header):
  # Returns true if source and header are a matched pair.
  # Source is the path on disk to the source file and header is the include
  # reference to the header (i.e., "blah/foo.h" or <blah/foo.h> including the
  # outer quotes or brackets.
  if not _CC_SOURCES_RE.match(source_path):
    return False

  source_root = os.path.splitext(source_path)[0]
  if source_root.endswith('_unittest'):
    source_root = source_root[0:-9]
  include = os.path.normpath(source_root + '.h')
  header = os.path.normpath(header[1:-1])

  return include.endswith(header)


def _GetHeaderCompareKey(source_path, header):
  if _IsSourceHeaderPair(source_path, header):
    # We put the header that corresponds to this source file first.
    group = 0
  elif header.startswith('<'):
    # C++ system headers should come after C system headers.
    group = 1 if header.endswith('.h>') else 2
  else:
    group = 3
  dirname, basename = os.path.split(header[1:-1])
  return (group, dirname, basename)


def _GetHeaderCompareKeyFunc(source):
  return lambda header : _GetHeaderCompareKey(source, header)


def _HeaderGroups(source_lines):
  # Generates lists of headers in source, one per block of headers.
  # Each generated value is a tuple (line, headers) denoting on which
  # line of the source file an uninterrupted sequences of includes begins,
  # and the list of included headers (paths including the quotes or angle
  # brackets).
  start_line, headers = None, []
  for line, num in itertools.izip(source_lines, itertools.count(1)):
    match = _INCLUDE_RE.match(line)
    if match:
      # The win32 api has all sorts of implicit include order dependencies.
      # Rather than encode exceptions for these, we require that they be
      # excluded from the ordering by a // NOLINT comment.
      if not match.group('nolint'):
        headers.append(match.group('header'))
      if start_line is None:
        # We just started a new run of headers.
        start_line = num
    elif headers and not _COMMENT_OR_BLANK_RE.match(line):
      # Any non-empty or non-comment line interrupts a sequence of includes.
      assert start_line is not None
      yield (start_line, headers)
      start_line = None
      headers = []

  # Just in case we have some headers we haven't yielded yet, this is our
  # last chance to do so.
  if headers:
    assert start_line is not None
    yield (start_line, headers)


def CheckIncludeOrder(input_api, output_api):
  """Checks that the C/C++ include order is correct."""
  errors = []
  is_cc_file = lambda x: input_api.FilterSourceFile(x, white_list=_CC_FILES)
  for f in input_api.AffectedFiles(include_deletes=False,
                                   file_filter=is_cc_file):
    for line_num, group in _HeaderGroups(f.NewContents()):
      sorted_group = sorted(group, key=_GetHeaderCompareKeyFunc(f.LocalPath()))
      if group != sorted_group:
        message = '%s, line %s: Out of order includes. ' \
                  'Expected:\n\t#include %s' % (
                      f.LocalPath(),
                      line_num,
                      '\n\t#include '.join(sorted_group))
        errors.append(output_api.PresubmitPromptWarning(message))
  return errors


def CheckUnittestsRan(input_api, output_api, committing, configuration):
  """Checks that the unittests success file is newer than any modified file"""
  return presubmit.CheckTestSuccess(input_api, output_api, committing,
                                    configuration, 'ALL',
                                    message=_UNITTEST_MESSAGE % configuration)


def CheckEnforcedChanges(input_api, output_api, committing, enforced):
  """Enforces changes based on the provided rules.

  |enforced| is a list of 2-tuples, where each entry is a list of file
  names relative to the repository root. If all of the files in
  the first list have been changed, then all of the files in the second
  list must also be changed.
  """

  errors = []

  changed = {}
  for f in input_api.AffectedFiles(include_deletes=False):
    changed[f.LocalPath()] = True

  for (a, b) in enforced:
    all_changed = all(changed.get(f, False) for f in a)
    if not all_changed:
      continue

    for f in b:
      if f not in changed:
        errors.append(output_api.PresubmitPromptWarning(
            '%s needs to be updated.' % f))

  return errors


def CheckReleaseNotes(input_api, output_api, committing):
  version = os.path.join('syzygy', 'VERSION')
  release_notes = os.path.join('syzygy', 'build', 'RELEASE-NOTES.TXT')
  return CheckEnforcedChanges(input_api, output_api, committing,
                              [[[version], [release_notes]]])


def CheckReadMe(input_api, output_api, committing):
  binaries = os.path.join('syzygy', 'build', 'binaries.gypi')
  readme = os.path.join('syzygy', 'build', 'README.TXT.template')
  return CheckEnforcedChanges(input_api, output_api, committing,
                              [[[binaries], [readme]]])


def CheckChange(input_api, output_api, committing):
  # The list of (canned) checks we perform on all files in all changes.
  checks = [
    CheckIncludeOrder,
    input_api.canned_checks.CheckChangeHasDescription,
    input_api.canned_checks.CheckChangeHasNoCrAndHasOnlyOneEol,
    input_api.canned_checks.CheckChangeHasNoTabs,
    input_api.canned_checks.CheckChangeHasNoStrayWhitespace,
    input_api.canned_checks.CheckChangeSvnEolStyle,
    input_api.canned_checks.CheckDoNotSubmit,
  ]

  results = []
  for check in checks:
    results += check(input_api, output_api)

  results += input_api.canned_checks.CheckLongLines(input_api, output_api, 80)

  # We run lint only on C/C++ files so that we avoid getting notices about
  # files being ignored.
  is_cc_file = lambda x: input_api.FilterSourceFile(x, white_list=_CC_FILES,
      black_list=_CC_FILES_BLACKLIST)
  results += input_api.canned_checks.CheckChangeLintsClean(
      input_api, output_api, source_file_filter=is_cc_file)

  # We check the license on the default recognized source file types, as well
  # as GYP and Python files.
  gyp_file_re = r'.+\.gypi?$'
  py_file_re = r'.+\.py$'
  white_list = input_api.DEFAULT_WHITE_LIST + (gyp_file_re, py_file_re)
  sources = lambda x: input_api.FilterSourceFile(x, white_list=white_list)
  results += input_api.canned_checks.CheckLicense(input_api,
                                                  output_api,
                                                  _LICENSE_HEADER,
                                                  source_file_filter=sources)

  results += CheckReleaseNotes(input_api, output_api, committing)
  results += CheckReadMe(input_api, output_api, committing)
  results += CheckUnittestsRan(input_api, output_api, committing, "Debug")
  results += CheckUnittestsRan(input_api, output_api, committing, "Release")

  if internal_presubmit:
    results += internal_presubmit.CheckChange(input_api,
                                              output_api,
                                              committing)

  return results


def CheckChangeOnUpload(input_api, output_api):
  return CheckChange(input_api, output_api, False)


def CheckChangeOnCommit(input_api, output_api):
  return CheckChange(input_api, output_api, True)
