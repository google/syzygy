# Copyright 2014 Google Inc. All Rights Reserved.
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
"""Unittests for gitdeps.py.

This test requires git to be in the path, and requires internet connectivity.
It runs tests against a repository hosted on github.com.
"""

import gitdeps
import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest


_LOGGER = logging.getLogger(os.path.basename(__file__))


def _Shell(*cmd, **kw):
  """Runs |cmd|, returning the results from Popen(cmd).communicate(). Additional
  keyword arguments are passed on to subprocess.Popen.
  """
  _LOGGER.debug('Executing %s.', cmd)
  kw['shell'] = True
  kw.setdefault('stdout', subprocess.PIPE)
  kw.setdefault('stderr', subprocess.PIPE)
  prog = subprocess.Popen(cmd, **kw)

  stdout, stderr = prog.communicate()
  if prog.returncode != 0:
    raise RuntimeError('Command "%s" returned %d.' % (cmd, prog.returncode))
  return (stdout, stderr)


class ScopedTempDir(object):
  """A class that creates a temporary directory that dies when it does."""

  def __init__(self):
    """Creates the temporary directory and initializes |path|."""
    self.path = tempfile.mkdtemp(prefix='gitdeps_test_')

  def __del__(self):
    """Destroys the temporary directory."""
    _Shell('rmdir', '/S', '/Q', self.path)


def _CountChildDirectories(path):
  """Returns the number of child directories there are in the given |path|."""
  for dummy_root, dirs, dummy_files in os.walk(path):
    return len(dirs)


def _WriteDeps(deps, path):
  """Writes the provided |deps| to the given |path|."""
  with open(path, 'wb') as io:
    io.write('deps = ')
    io.write(json.dumps(deps, indent=2))
    io.write('\n')


class TestGitDeps(unittest.TestCase):
  """Unittests for the gitdeps script."""

  def setUp(self):
    """Runs before every test in this fixture."""
    self._temp_dir = None
    self._dummy_repo_path = 'https://github.com/chhamilton/test_repo.git'

  def temp_dir(self):
    if self._temp_dir is None:
      self._temp_dir = ScopedTempDir()
    return self._temp_dir.path

  def tearDown(self):
    # This will lose the last reference to the temp directory and cause it to
    # be torn down.
    self._temp_dir = None

  def _BuildTestRepoPaths(self):
    """Sets up the various paths for checking out the test repo."""
    # pylint: disable=W0201
    self._cache_dir = os.path.join(self.temp_dir(), 'cache_dir')
    self._output_dir = os.path.join(self.temp_dir(), 'output_dir')
    self._checkout_dir_rel = 'repo'
    self._junctions_path = os.path.join(self._cache_dir, '.gitdeps_junctions')
    self._checkout_dir_abs = os.path.join(self._output_dir,
                                          self._checkout_dir_rel)
    self._script_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                     'gitdeps.py'))

  def _RunScript(self, cache_dir=None, output_dir=None, deps_paths=None,
                 verbose=False, cwd=None, stdout=None, stderr=None):
    """Runs the gitdeps.py script with the provided arguments. If |cache_dir|
    is not specified then defaults to self._cache_dir. If the other arguments
    are not specified then they are left unspecified on the command line.
    """
    if deps_paths is None:
      deps_paths = []
    cmd = [sys.executable,
           self._script_path,
           '--cache-dir=%s' % (cache_dir if cache_dir else self._cache_dir)]
    if output_dir:
      cmd.append('--output-dir=%s' % output_dir)
    if verbose:
      cmd.append('--verbose')
    cmd += deps_paths
    stdo, stde = _Shell(*cmd, cwd=cwd, stdout=stdout, stderr=stderr)
    return (stdo, stde)

  def _TestSuccessBasicCheckout(self,
                                create_cache_dir,
                                specify_output_dir,
                                specify_deps_file):
    self._BuildTestRepoPaths()

    # Determine 'cwd' and 'output_dir' parameters.
    output_dir = None
    cwd = self._output_dir
    if specify_output_dir:
      output_dir = self._output_dir
      cwd = None

    # Determine the deps file path.
    deps_path = os.path.join(self.temp_dir(), 'gitdeps.txt')
    deps_paths = [deps_path]
    if not specify_deps_file:
      if not cwd:
        cwd = self.temp_dir()
      deps_path = os.path.join(cwd, 'GITDEPS')
      deps_paths = []

    # Create the directories.
    if create_cache_dir:
      os.mkdir(self._cache_dir)
    os.mkdir(self._output_dir)

    # Create and write the deps file.
    deps = {
      self._checkout_dir_rel: (self._dummy_repo_path, 'foo', 'rev2')
    }
    _WriteDeps(deps, deps_path)

    # Run the script.
    self._RunScript(output_dir=output_dir,
                    deps_paths=deps_paths,
                    verbose=True,
                    cwd=cwd)

    # Ensure the checkout was created as expected.
    self.assertTrue(os.path.isdir(self._cache_dir))
    self.assertEqual(1, _CountChildDirectories(self._cache_dir))
    self.assertTrue(os.path.isfile(self._junctions_path))
    self.assertTrue(os.path.isdir(self._checkout_dir_abs))
    # pylint: disable=W0212
    self.assertNotEqual(None, gitdeps._GetJunctionInfo(self._checkout_dir_abs))

  # The following batch of tests covers basic differences in command-line
  # options.
  def testSuccessEmptyCacheDirEmptyOutputDirSpecifiedDeps(self):
    self._TestSuccessBasicCheckout(True, True, True)

  def testSuccessEmptyCacheDirEmptyOutputDirImplicitDeps(self):
    self._TestSuccessBasicCheckout(True, True, False)

  def testSuccessEmptyCacheDirNoOutputDirSpecifiedDeps(self):
    self._TestSuccessBasicCheckout(True, False, True)

  def testSuccessEmptyCacheDirNoOutputDirImplicitDeps(self):
    self._TestSuccessBasicCheckout(True, False, False)

  def testSuccessNoCacheDirEmptyOutputDirSpecifiedDeps(self):
    self._TestSuccessBasicCheckout(False, True, True)

  def testSuccessNoCacheDirEmptyOutputDirImplicitDeps(self):
    self._TestSuccessBasicCheckout(False, True, False)

  def testSuccessNoCacheDirNoOutputDirSpecifiedDeps(self):
    self._TestSuccessBasicCheckout(False, False, True)

  def testSuccessNoCacheDirNoOutputDirImplicitDeps(self):
    self._TestSuccessBasicCheckout(False, False, False)

  def _TestSuccessCheckoutReuse(self, reuse_refspec):
    """A test that checks reuse of a cached repository by checking out a
    second time with a different refspec.
    """
    self._TestSuccessBasicCheckout(True, True, True)

    # Create and write the deps file.
    deps_path = os.path.join(self.temp_dir(), 'gitdeps.txt')
    deps = {
      self._checkout_dir_rel: (self._dummy_repo_path, 'foo', reuse_refspec)
    }
    _WriteDeps(deps, deps_path)

    # Run the script.
    self._RunScript(output_dir=self._output_dir,
                    deps_paths=[deps_path],
                    verbose=True)

    # Ensure the checkout was created as expected.
    self.assertTrue(os.path.isdir(self._cache_dir))
    self.assertEqual(1, _CountChildDirectories(self._cache_dir))
    self.assertTrue(os.path.isfile(self._junctions_path))
    self.assertTrue(os.path.isdir(self._checkout_dir_abs))
    # pylint: disable=W0212
    self.assertNotEqual(None, gitdeps._GetJunctionInfo(self._checkout_dir_abs))

  def testCheckoutReuseForwards(self):
    """Tests that repository reuse is okay when moving to a child reference."""
    self._TestSuccessCheckoutReuse('master')

  def testCheckoutReuseBackwards(self):
    """Tests that repository reuse is okay when moving to a parent reference."""
    self._TestSuccessCheckoutReuse('rev1')

  def testMultipleAndRemovedCheckouts(self):
    """Tests that multiple repository checkouts works, as well as removal of
    orphaned checkouts due to removal from the deps file.
    """
    self._BuildTestRepoPaths()
    os.mkdir(self._cache_dir)
    os.mkdir(self._output_dir)

    checkout_dir_rel2 = 'repo2/nested'
    checkout_dir_abs2 = os.path.join(self._output_dir, checkout_dir_rel2)

    # Create and write the deps file.
    deps_path = os.path.join(self.temp_dir(), 'gitdeps.txt')
    deps = {
      self._checkout_dir_rel: (self._dummy_repo_path, 'foo', 'rev2'),
      checkout_dir_rel2: (self._dummy_repo_path, 'foo', 'rev3')
    }
    _WriteDeps(deps, deps_path)

    # Run the script.
    self._RunScript(output_dir=self._output_dir,
                    deps_paths=[deps_path],
                    verbose=True)

    # Ensure the checkout was created as expected.
    self.assertTrue(os.path.isdir(self._cache_dir))
    self.assertEqual(2, _CountChildDirectories(self._cache_dir))
    self.assertTrue(os.path.isfile(self._junctions_path))
    self.assertTrue(os.path.isdir(self._checkout_dir_abs))
    # pylint: disable=W0212
    self.assertNotEqual(None, gitdeps._GetJunctionInfo(self._checkout_dir_abs))
    self.assertTrue(os.path.isdir(checkout_dir_abs2))
    # pylint: disable=W0212
    self.assertNotEqual(None, gitdeps._GetJunctionInfo(checkout_dir_abs2))

    # Rewrite the deps file, removing the nested junction.
    deps = {
      self._checkout_dir_rel: (self._dummy_repo_path, 'foo', 'rev2'),
    }
    _WriteDeps(deps, deps_path)

    # Run the script.
    self._RunScript(output_dir=self._output_dir,
                    deps_paths=[deps_path],
                    verbose=True)

    # Ensure the checkout was created as expected.
    self.assertTrue(os.path.isdir(self._cache_dir))
    self.assertEqual(1, _CountChildDirectories(self._cache_dir))
    self.assertTrue(os.path.isfile(self._junctions_path))
    self.assertTrue(os.path.isdir(self._checkout_dir_abs))
    self.assertNotEqual(None, gitdeps._GetJunctionInfo(self._checkout_dir_abs))

    # repo2/nested shouldn't exist, but neither should repo2 (as the directory
    # is empty and should have been removed).
    self.assertFalse(os.path.exists(checkout_dir_abs2))
    self.assertFalse(os.path.exists(os.path.dirname(checkout_dir_abs2)))


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  unittest.main()
