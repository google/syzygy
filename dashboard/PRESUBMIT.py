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
# Presubmit script for Syzygy Dashboard. These are run in addition to
# those checks in syzygy/PRESUBMIT.py.

import os
import re
import sys


# We can't use __file__ as the contents of this file are slurped into a string
# by gcl/git-cl, and interpreted. However, we are guaranteed that the working
# directory will be set to the directory where this file resides. Hence the
# path trickery.
sys.path.insert(0, os.path.join(os.getcwd(), '..', 'py', 'test_utils'))
import presubmit


# This is sent during a commit of a change to app.yaml.
_PUSH_MESSAGE = 'After committing, please push the new version of Syzygy ' \
                'Dashboard to the AppEngine backend at: ' \
                'https://appengine.google.com'


class PresubmitError(Exception):
  """An error type used to indicate presubmit failure."""
  pass


def _LoadVersionFile():
  """Reads the version from the VERSION file, returning it as a dict with
  strings keys 'MAJOR', 'MINOR', etc.

  Raises:
    PresubmitError: if VERSION file is malformed in any way.
  """
  expected_keys = [ 'MAJOR', 'MINOR', 'BUILD', 'PATCH' ]
  version_path = os.path.join(os.getcwd(), '..', 'VERSION')
  version = {}
  for line in open(version_path, 'rb'):
    match = re.match('^([A-Z]+)=([0-9]+)', line)
    if match:
      if match.group(1) not in expected_keys:
        raise PresubmitError('Unexpected VERSION key: %s' % match.group(1))
      version[match.group(1)] = int(match.group(2))

  # Ensure that all keys were present.
  missing = [key for key in expected_keys if not version.has_key(key)]
  if missing:
    raise PresubmitError('Missing VERSION keys: %s' % ', '.join(missing))

  return version


def CheckDashboardVersion(input_api, output_api, committing):
  """If app.yaml is being changed ensure that the version is consistent with
  the current toolchain version, and gently remind the user that a new push
  needs to be made to the AppEngine back-end.
  """

  results = []

  try:
    app_yaml = os.path.join('syzygy', 'dashboard', 'app.yaml')
    for af in input_api.AffectedFiles():
      if app_yaml == af.LocalPath():
        # Print a friendly reminder that we should push the new version of
        # Syzygy Dashboard to AppEngine.
        if committing:
          results.append(output_api.PresubmitNotifyResult(_PUSH_MESSAGE))

        version = _LoadVersionFile()
        expected_version = '%(MAJOR)d-%(MINOR)d-%(BUILD)d-%(PATCH)d' % version

        # Loop through app.yaml, looking for the version string.
        version_found = False
        for line in open(af.AbsoluteLocalPath(), "rb"):
          match = re.match('^version:\s*([^\s]+)', line)
          if match:
            version_found = True
            if expected_version != match.group(1):
              raise PresubmitError('Got version "%s", expected "%s".' %
                  (match.group(1), expected_version))

            # The version was good, so we can break from the loop.
            break

        if not version_found:
          raise PresubmitError('No version found.')

  # Catch any presubmit errors and convert them to OutputApi messages.
  except PresubmitError, e:
    results.append(
        presubmit.MakeResult(output_api, e.args[0], committing, [af]))

  return results


def CheckChange(input_api, output_api, committing):
  checks = [
    CheckDashboardVersion
  ]

  results = []
  for check in checks:
    results += check(input_api, output_api, committing)


  # We only check Python files in this directory. The others are checked by
  # the PRESUBMIT in our root directory.
  sys.path.append('../../third_party/googleappengine')
  white_list = [r'^.*\.py$']
  black_list = [r'^ez_setup\.py$']
  disabled_warnings = [
      # Differing number of arguments in override. We often override using
      # a different signature than in the base class (using *args, **kwargs
      # for things we don't care about, and simply passing them through).
      'W0221',
      # The Google AppEngine API seems to have runtime generated functions
      # which pylint doesn't detect. It consistently complains that we are
      # calling non-existing member functions, so we ignore this globally.
      'E1101', 'E1103']
  results += input_api.canned_checks.RunPylint(input_api, output_api,
      white_list=white_list, black_list=black_list,
      disabled_warnings=disabled_warnings)


  return results


def CheckChangeOnUpload(input_api, output_api):
  return CheckChange(input_api, output_api, False)


def CheckChangeOnCommit(input_api, output_api):
  return CheckChange(input_api, output_api, True)
