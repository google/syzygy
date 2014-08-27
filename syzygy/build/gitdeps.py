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
"""A utility script for checking out subdirectories of many GIT repositories
to specified locations, like is possible with SVN and gclient. This uses a
combination of GIT, sparse-checkout, shallow-clone and filesystem junctions.

For each dependency in a 'gitdeps' file this script will checkout one
subdirectory of one repository into a specified location. The input is as
follows:

- The user specifies a local destination for the checkout.
- The user specifies a source repository.
- The user specifies a subdirectory of the repository.
- The user specifies a revision.

The checkout works as follows:

- An empty git checkout is initialized in the cache directory. This will be
  in a subfolder with an essentially random name.
- The specified repository is added as a remote to that repo.
- A sparse-checkout directive is added to select only the desired subdirectory.
- The repository is cloned using a depth of 1 (no history, only the actual
  contents of the desired revision).
- The destination directory is created as a junction pointing to the
  subdirectory of the checkout in the cache directory.

The script maintains its state in the root of the cache directory, allowing it
to reuse checkout directories when possible.
"""

import ast
import glob
import hashlib
import logging
import optparse
import os
import random
import re
import subprocess
import threading


_LOGGER = logging.getLogger(os.path.basename(__file__))


# Matches a SHA1 hash used as a git revision.
_GIT_SHA1_RE = re.compile('^[A-Fa-f0-9]{40}$')


def _ParseCommandLine():
  """Parses the command-line and returns an options structure."""
  option_parser = optparse.OptionParser()
  option_parser.add_option('--cache-dir', type='string',
      default='.gitdeps-cache',
      help='The directory to be used for storing cache files. Defaults to '
           '.gitdeps-cache in the current working directory.')
  option_parser.add_option('--output-dir', type='string', default='.',
      help='The directory to be used as the root of all output. Defaults to '
           'the current working directory.')
  option_parser.add_option('--dry-run', action='store_true', default=False,
      help='If true then will simply list actions that would be performed.')
  option_parser.add_option('--force', action='store_true', default=False,
      help='If true then will force the checkout to be completely rebuilt.')
  option_parser.add_option('--verbose', dest='log_level', action='store_const',
      default=logging.INFO, const=logging.DEBUG,
      help='Enables verbose logging.')
  option_parser.add_option('--quiet', dest='log_level', action='store_const',
      default=logging.INFO, const=logging.ERROR,
      help='Disables all output except for errors.')

  options, args = option_parser.parse_args()

  # Configure logging.
  logging.basicConfig(level=options.log_level)

  # Set default values.
  if not args:
    # Default to checking for a file in the current working directory.
    _LOGGER.info('Defaulting to using GITDEPS in current working directory.')
    args = ['GITDEPS']

  # Validate arguments and options.
  if not os.path.isdir(options.output_dir):
    option_parser.error('Output directory does not exist: %s' %
        options.output_dir)
  for path in args:
    if not os.path.exists(path):
      option_parser.error('Missing dependency file: %s' % path)

  # Normalize local paths for prettier output.
  options.cache_dir = os.path.normpath(os.path.abspath(options.cache_dir))
  options.output_dir = os.path.normpath(os.path.abspath(options.output_dir))

  return options, args


class RepoOptions(object):
  """Light object used for shuttling around information about a dependency."""

  def __init__(self):
    self.repository = None
    self.revision = None
    self.output_dir = None
    self.remote_dir = None
    self.deps_file = None
    self.checkout_dir = None

  def __str__(self):
    """Stringifies this object for debugging."""
    return ('RepoOptions(repository=%s, revision=%s, output_dir=%s, '
            'remote_dir=%s, deps_file=%s, checkout_dir=%s)') % (
                self.repository.__repr__(),
                self.revision.__repr__(),
                self.output_dir.__repr__(),
                self.remote_dir.__repr__(),
                self.deps_file.__repr__(),
                self.checkout_dir.__repr__())


def _ParseRepoOptions(cache_dir, root_output_dir, deps_file_path, key, value):
  """Given the |root_output_dir| specified on the command line, a |key| and
  |value| pair from a GITDEPS file, and the path of the deps file, generates
  a corresponding RepoOptions object. The |key| is the output path of the
  checkout relative to |root_output_dir|, and |value| consists of a
  (repository URL, remote directory, revision hash) tuple. This can raise an
  Exception on failure.
  """
  if (type(value) != list and type(value) != tuple) or len(value) != 3:
    _LOGGER.error('Invalid dependency tuple: %s', value)
    raise Exception()

  # Always use lowercase SHA1 hashes for consistency.
  refspec = value[2]
  if _GIT_SHA1_RE.match(refspec):
    refspec = refspec.lower()

  repo_options = RepoOptions()
  repo_options.output_dir = os.path.normpath(os.path.abspath(os.path.join(
      root_output_dir, key)))
  repo_options.repository = value[0]
  repo_options.remote_dir = value[1]
  repo_options.revision = refspec
  repo_options.deps_file = deps_file_path

  # Create a unique name for the checkout in the cache directory. Make the
  # output directory relative to the cache directory so that they can be
  # moved around together.
  output_dir_rel = os.path.relpath(repo_options.output_dir,
                                   root_output_dir).lower()
  if output_dir_rel.startswith('..'):
    raise Exception('Invalid output directory: %s' % key)
  n = hashlib.md5(output_dir_rel).hexdigest()
  repo_options.checkout_dir = os.path.abspath(os.path.join(cache_dir, n))

  return repo_options


def _EnsureDirectoryExists(path, comment_name, dry_run):
  """Ensures that the given |path| exists. Only actually creates the directory
  if |dry_run| is False. |comment_name| is used during logging of this
  operation.
  """
  if not comment_name:
    comment_name += ' '
  else:
    comment_name = ''
  if not os.path.exists(path):
    _LOGGER.debug('Creating %sdirectory: %s', comment_name, path)
    if not dry_run:
      os.makedirs(path)


def _GetCasedFilename(filename):
  """Returns the full case-sensitive filename for the given |filename|. If the
  path does not exist, returns the original |filename| as is.
  """
  pattern = '%s[%s]' % (filename[:-1], filename[-1])
  filenames = glob.glob(pattern)
  if not filenames:
    return filename
  return filenames[0]


def _Shell(*cmd, **kw):
  """Runs |cmd|, returns the results from Popen(cmd).communicate(). Additional
  keyword arguments are passed on to subprocess.Popen. If |stdout| and |stderr|
  are not specified, they default to subprocess.PIPE. If |dry_run| is not
  specified it defaults to True. The command is only actually run if |dry_run|
  is False. This can raise a RuntimeError on failure.
  """
  if 'cwd' in kw:
    _LOGGER.debug('Executing %s in "%s".', cmd, kw['cwd'])
  else:
    _LOGGER.debug('Executing %s.', cmd)
  if kw.get('dry_run', True):
    return ('', '')
  kw.pop('dry_run', None)
  dump_on_error = kw.pop('dump_on_error', False)

  kw['shell'] = True
  kw.setdefault('stdout', subprocess.PIPE)
  kw.setdefault('stderr', subprocess.PIPE)
  prog = subprocess.Popen(cmd, **kw)

  stdout, stderr = prog.communicate()
  if prog.returncode != 0:
    if dump_on_error:
      print stdout
      print stderr
    raise RuntimeError('Command "%s" returned %d.' % (cmd, prog.returncode))
  return (stdout, stderr)


def _IsGitCheckoutRoot(path):
  """Return true if the given |path| is the root of a git checkout."""
  return os.path.exists(os.path.join(path, '.git'))


# Matches a GIT config file section header, and grabs the name of the section
# in the first group. Used by _GetGitOrigin.
_GIT_CONFIG_SECTION_RE = re.compile(r'^\s*\[(.*?)\]\s*$')
# Matches the URL line from a 'remote' section of a GIT config. Used by
# _GetGitOrigin.
_GIT_CONFIG_REMOTE_URL_RE = re.compile(r'^\s*url\s*=\s*(.*?)\s*$')


def _GetGitOrigin(path):
  """Returns the URL of the 'origin' remote for the git repo in |path|. Returns
  None if the 'origin' remote doesn't exist. Raises an IOError if |path| doesn't
  exist or is not a git repo.
  """
  section = None
  for line in open(os.path.join(path, '.git', 'config'), 'rb'):
    m = _GIT_CONFIG_SECTION_RE.match(line)
    if m:
      section = m.group(1)
      continue

    # We only care about the 'origin' configuration.
    if section != 'remote "origin"':
      continue

    m = _GIT_CONFIG_REMOTE_URL_RE.match(line)
    if m:
      return m.group(1).strip()

  return None


def _GetGitHead(path):
  """Returns the hash of the head of the git repo in |path|. Raises an IOError
  if |path| doesn't exist or is not a git repo.
  """
  return open(os.path.join(path, '.git', 'HEAD'), 'rb').read().strip()


def _NormalizeGitPath(path):
  """Given a |path| in a GIT repository (relative to its root), normalizes it so
  it will match only that exact path in a sparse checkout.
  """
  path = path.strip()
  if not path.startswith('/'):
    path = '/' + path
  if not path.endswith('/'):
    path += '/'
  return path


def _RenameCheckout(path, dry_run):
  """Renames the checkout in |path| so that it can be subsequently deleted.
  Only actually does the work if |dry_run| is False. Returns the path of the
  renamed checkout directory. Raises an Exception on failure.
  """

  def _RenameCheckoutImpl(path, dry_run):
    if dry_run:
      return path + '-old-dryrun'
    attempts = 0
    while attempts < 10:
      newpath = '%s-old-%04d' % (path, random.randint(0, 999))
      try:
        os.rename(path, newpath)
        return newpath
      except WindowsError:
        attempts += 1
    raise Exception('Unable to rename checkout directory: %s' % path)

  newpath = _RenameCheckoutImpl(path, dry_run)
  _LOGGER.debug('Renamed checkout directory: %s', newpath)
  return newpath


def _DeleteCheckout(path, dry_run):
  """Deletes the checkout in |path|. Only actually deletes the checkout if
  |dry_run| is False.
  """
  _LOGGER.debug('Deleting checkout directory: %s', path)
  if dry_run:
    return
  _Shell('rmdir', '/S', '/Q', path, dry_run=False)


def _GenerateSparseCheckoutPathAndContents(repo):
  """Generates the path to the sparse checkout file, and the desired
  contents. Returns a tuple of (path, contents). |repo| is a RepoOptions object.
  """
  sparse_file = os.path.join(repo.checkout_dir, '.git', 'info',
                             'sparse-checkout')
  if not repo.remote_dir:
    contents = '*\n'
  else:
    contents = _NormalizeGitPath(repo.remote_dir) + '\n'
  return (sparse_file, contents)


def _HasValidSparseCheckoutConfig(repo):
  """Determines if the GIT repo in |path| has a valid sparse-checkout
  configuration as configured by the RepoOptions |repo|. Returns True or False.
  """
  (sparse_file, contents) = _GenerateSparseCheckoutPathAndContents(repo)
  try:
    if open(sparse_file, 'rb').read() == contents:
      return True
    return False
  except IOError:
    return False


def _CreateCheckout(path, repo, dry_run):
  """Creates a checkout in the provided |path|. The |path| must not already
  exist. Uses the repository configuration from the provided |repo| RepoOptions
  object. Only actually creates the checkout if |dry_run| is false.
  """
  # We expect the directory not to exist, as this is a fresh checkout we are
  # creating.
  if not dry_run:
    if os.path.exists(path):
      raise Exception('Checkout directory already exists: %s' % path)

  _LOGGER.debug('Creating checkout directory: %s', path)
  if not dry_run:
    os.makedirs(path)

  _LOGGER.debug('Initializing the checkout.')
  _Shell('git', 'init', cwd=path, dry_run=dry_run)
  _Shell('git', 'remote', 'add', 'origin', repo.repository, cwd=path,
         dry_run=dry_run)
  _Shell('git', 'config', 'core.sparsecheckout', 'true', cwd=path,
         dry_run=dry_run)
  if not dry_run:
    _LOGGER.debug('Creating sparse checkout configuration file for '
                  'directory: %s', repo.remote_dir)
    if not dry_run:
      (path, contents) = _GenerateSparseCheckoutPathAndContents(repo)
      with open(path, 'wb') as io:
        io.write(contents)


def _UpdateCheckout(path, repo, dry_run):
  """Updates a GIT checkout in |path| by pulling down a specific revision
  from it, as configured by RepoOptions |repo|. Only actually runs if
  |dry_run| is False.
  """
  try:
    # Try a checkout first. If this fails then we'll actually need to fetch
    # the revision.
    _LOGGER.debug('Trying to checkout revision %s.', repo.revision)
    _Shell('git', 'checkout', repo.revision, cwd=path,
          dry_run=dry_run)
    return
  except RuntimeError:
    pass

  # Fetch the revision and then check it out. Let output go to screen rather
  # than be buffered.
  _LOGGER.debug('Fetching and checking out revision %s.', repo.revision)
  _Shell('git', 'fetch', '--depth=1', 'origin', repo.revision,
         cwd=path, dry_run=dry_run, stdout=None, stderr=None)
  _Shell('git', 'checkout', repo.revision, cwd=path,
         dry_run=dry_run, stdout=None, stderr=None)


# Used by _GetJunctionInfo to extract information about junctions for the
# output of a 'dir' command.
_DIR_JUNCTION_RE = re.compile(r'^.*<JUNCTION>\s+(.+)\s+\[(.+)\]$')


# TODO(chrisha): This is ugly, and there has to be a better way!
def _GetJunctionInfo(junction):
  """Returns the target of a junction, if it exists, None otherwise."""
  dirname = os.path.dirname(junction)
  basename = os.path.basename(junction)
  stdout, dummy_stderr = _Shell('dir', '/AL', '/N', dirname, dry_run=False)
  for line in stdout.splitlines(False):
    m = _DIR_JUNCTION_RE.match(line)
    if not m:
      continue
    if m.group(1).lower() == basename.lower():
      return m.group(2)
  return None


def _EnsureJunction(cache_dir, options, repo):
  """Ensures that the appropriate junction exists from the configured output
  directory to the specified sub-directory of the GIT checkout.
  """
  # Ensure that the target directory was created.
  target_dir = _GetCasedFilename(os.path.normpath(
      os.path.join(cache_dir, repo.remote_dir)))
  if not options.dry_run and not os.path.isdir(target_dir):
    raise Exception('Checkout does not contain the desired remote folder.')

  # Determine if the link needs to be created.
  create_link = True
  if os.path.exists(repo.output_dir):
    dest = _GetJunctionInfo(repo.output_dir)
    if dest is None:
      raise Exception(
          'Target exists and is not a junction: %s' % repo.output_dir)

    # If the junction is valid nothing needs to be done. If it points to the
    # wrong place then delete the existing junction and let it be remade.
    if dest == target_dir:
      _LOGGER.debug('Junction is up to date.')
      create_link = False
    else:
      _LOGGER.debug('Erasing existing junction: %s', repo.output_dir)
      _Shell('rmdir', '/S', '/Q', repo.output_dir, dry_run=options.dry_run)

  if create_link:
    _LOGGER.debug('Creating output junction: %s', repo.output_dir)
    _Shell('mklink', '/J', repo.output_dir, target_dir,
           dry_run=options.dry_run)


def _InstallRepository(options, repo):
  """Installs a repository as configured by the options. Assumes that the
  specified cache directory already exists.
  """

  _LOGGER.debug('Processing directory "%s" from repository "%s".',
                repo.remote_dir, repo.repository)

  # Ensure the output directory's *parent* exists.
  output_dirname = os.path.dirname(repo.output_dir)
  output_basename = os.path.basename(repo.output_dir)
  _EnsureDirectoryExists(output_dirname, 'output', options.dry_run)

  # Get the properly cased names for the output directories.
  output_dirname = _GetCasedFilename(output_dirname)
  repo.output_dir = os.path.join(output_dirname, output_basename)

  # These are the 3 basic steps that need to occur. Depending on the state of
  # the checkout we may not need to perform all of them. We assume initially
  # that everything needs to be done, unless proven otherwise.
  create_checkout = True
  update_checkout = True

  # If the cache directory exists then lookup the repo and the revision and see
  # what needs to be updated.
  threads = []
  if os.path.exists(repo.checkout_dir):
    keep_cache_dir = False

    # Only run these checks if we're not in 'force' mode. Otherwise, we
    # deliberately turf the cache directory and start from scratch.
    if not options.force and _IsGitCheckoutRoot(repo.checkout_dir):
      # Get the repo origin.
      repo_url = _GetGitOrigin(repo.checkout_dir)
      if (repo_url == repo.repository and
          _HasValidSparseCheckoutConfig(repo)):
        _LOGGER.debug('Checkout is for correct repository and subdirectory.')
        keep_cache_dir = True
        create_checkout = False

        # Get the checked out revision.
        revhash = _GetGitHead(repo.checkout_dir)
        if revhash == repo.revision:
          _LOGGER.debug('Checkout is already up to date.')
          update_checkout = False

    if not keep_cache_dir:
      # The old checkout directory is renamed and erased in a separate thread
      # so that the new checkout can start immediately.
      _LOGGER.debug('Erasing stale checkout directory: %s', repo.checkout_dir)
      newpath = _RenameCheckout(repo.checkout_dir, options.dry_run)
      body = lambda: _DeleteCheckout(newpath, options.dry_run)
      thread = threading.Thread(target=body)
      threads.append(thread)
      thread.start()

  # Create and update the checkout as necessary.
  if create_checkout:
    _CreateCheckout(repo.checkout_dir, repo, options.dry_run)
  else:
    _LOGGER.debug('Reusing checkout directory: %s', repo.checkout_dir)
  if update_checkout:
    _UpdateCheckout(repo.checkout_dir, repo, options.dry_run)

  # Ensure the junction exists.
  _EnsureJunction(repo.checkout_dir, options, repo)

  # Join any worker threads that are ongoing.
  for thread in threads:
    thread.join()


def _FindGlobalVariableInAstTree(tree, name, functions=None):
  """Finds and evaluates to global assignment of the variables |name| in the
  AST |tree|. Will allow the evaluations of some functions as defined in
  |functions|.
  """
  if functions is None:
    functions = {}

  class FunctionEvaluator(ast.NodeTransformer):
    """A tree transformer that evaluates permitted functions."""

    def visit_BinOp(self, binop_node):
      """Is called for BinOp nodes. We only support string additions."""
      if type(binop_node.op) != ast.Add:
        return binop_node
      left = ast.literal_eval(self.visit(binop_node.left))
      right = ast.literal_eval(self.visit(binop_node.right))
      value = left + right
      new_node = ast.Str(s=value)
      new_node = ast.copy_location(new_node, binop_node)
      return new_node

    def visit_Call(self, call_node):
      """Evaluates function calls that return a single string as output."""
      func_name = call_node.func.id
      if func_name not in functions:
        return call_node
      func = functions[func_name]

      # Evaluate the arguments. We don't care about starargs, keywords or
      # kwargs.
      args = [ast.literal_eval(self.visit(arg)) for arg in
                  call_node.args]

      # Now evaluate the function.
      value = func(*args)
      new_node = ast.Str(s=value)
      new_node = ast.copy_location(new_node, call_node)
      return new_node

  # Look for assignment nodes.
  for node in tree.body:
    if type(node) != ast.Assign:
      continue
    # Look for assignment in the 'store' context, to a variable with
    # the given name.
    for target in node.targets:
      if type(target) != ast.Name:
        continue
      if type(target.ctx) != ast.Store:
        continue
      if target.id == name:
        value = FunctionEvaluator().visit(node.value)
        value = ast.fix_missing_locations(value)
        value = ast.literal_eval(value)
        return value


def _ParseDepsFile(path):
  """Parsed a DEPS-like file at the given |path|."""
  # Utility function for performing variable expansions.
  vars_dict = {}
  def _Var(s):
    return vars_dict[s]

  contents = open(path, 'rb').read()
  tree = ast.parse(contents, path)
  vars_dict = _FindGlobalVariableInAstTree(tree, 'vars')
  deps_dict = _FindGlobalVariableInAstTree(
      tree, 'deps', functions={'Var': _Var})
  return deps_dict


def _RemoveOrphanedJunction(options, junction):
  """Removes an orphaned junction at the path |junction|. If the path doesn't
  exist or is not a junction, raises an Exception.
  """
  _LOGGER.debug('Removing orphaned junction: %s', junction)
  absdir = os.path.join(options.output_dir, junction)
  if not _GetJunctionInfo(absdir):
    _LOGGER.error('Path is not a junction: %s', absdir)
    raise Exception()
  _Shell('rmdir', '/S', '/Q', absdir, dry_run=options.dry_run)

  reldir = os.path.dirname(junction)
  while reldir:
    print reldir
    absdir = os.path.join(options.output_dir, reldir)
    if os.listdir(absdir):
      return
    _LOGGER.debug('Removing empty parent directory of junction: %s', absdir)
    _Shell('rmdir', '/S', '/Q', absdir, dry_run=options.dry_run)
    reldir = os.path.dirname(reldir)


def main():
  options, args = _ParseCommandLine()

  # Ensure the cache directory exists and get the full properly cased path to
  # it.
  _EnsureDirectoryExists(options.cache_dir, 'cache', options.dry_run)
  options.cache_dir = _GetCasedFilename(options.cache_dir)

  # Read junctions that have been written in previous runs.
  state_path = os.path.join(options.cache_dir, '.gitdeps_junctions')
  old_junctions = {}
  if os.path.exists(state_path):
    _LOGGER.debug('Loading list of existing junctions.')
    for j in open(state_path, 'rb'):
      old_junctions[j.strip()] = True

  # Parse each deps file in order, and extract the dependencies, looking for
  # conflicts in the output directories.
  output_dirs = {}
  all_deps = []
  for deps_file in args:
    deps = _ParseDepsFile(deps_file)
    for key, value in deps.iteritems():
      repo_options = _ParseRepoOptions(
          options.cache_dir, options.output_dir, deps_file, key, value)
      if repo_options.output_dir in output_dirs:
        other_repo_options = output_dirs[repo_options.output_dir]
        _LOGGER.error('Conflicting output directory: %s',
                      repo_options.output_dir)
        _LOGGER.error('First specified in file: %s',
                      other_repo_options.deps_file)
        _LOGGER.error('And then specified in file: %s', repo_options.deps_file)
      output_dirs[repo_options.output_dir] = repo_options
      all_deps.append(repo_options)
  output_dirs = {}

  # Handle each dependency, in order of shortest path names first. This ensures
  # that nested dependencies are handled properly.
  checkout_dirs = {}
  deps = sorted(all_deps, key=lambda x: len(x.deps_file))
  junctions = []
  for repo in all_deps:
    _InstallRepository(options, repo)
    checkout_dirs[repo.checkout_dir] = True
    junction = os.path.relpath(repo.output_dir, options.output_dir)
    old_junctions.pop(junction, None)
    # Write each junction as we create it. This allows for recovery from
    # partial runs.
    if not options.dry_run:
      open(state_path, 'ab').write(junction + '\n')
      junctions.append(junction)

  # Clean up orphaned junctions if there are any.
  if old_junctions:
    _LOGGER.debug('Removing orphaned junctions.')
    for j in old_junctions.iterkeys():
      _RemoveOrphanedJunction(options, j)

  # Output the final list of junctions.
  _LOGGER.debug('Writing final list of junctions.')
  if not options.dry_run:
    with open(state_path, 'wb') as io:
      for j in sorted(junctions):
        io.write(j)
        io.write('\n')

  # Iterate all directories in the cache directory. Any that we didn't
  # specifically create or update should be cleaned up. Do this in parallel
  # so things are cleaned up as soon as possible.
  threads = []
  for path in glob.glob(os.path.join(options.cache_dir, '*')):
    if path not in checkout_dirs:
      _LOGGER.debug('Erasing orphaned checkout directory: %s', path)
      body = lambda: _DeleteCheckout(path, options.dry_run)
      thread = threading.Thread(target=body)
      threads.append(thread)
      thread.start()
  for thread in threads:
    thread.join()

  return


if __name__ == '__main__':
  main()
