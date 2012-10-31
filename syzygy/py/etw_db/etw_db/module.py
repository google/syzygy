#!python
# Copyright 2011 Google Inc. All Rights Reserved.
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
"""Provides an event consumer that tracks image events."""
from etw import EventConsumer, EventHandler
import etw.descriptors.image as image
import etw.descriptors.process as process


class _Module(object):
  """Store the state for a single loaded module."""
  def __init__(self, event):
    """Initializes a module object from a module load event."""
    self.module_base = event.ImageBase
    self.module_size = event.ImageSize
    self.file_name = event.FileName

  def __repr__(self):
    return '0x%08X(0x%08X): %s' % (self.module_base,
                                   self.module_size,
                                   self.file_name)


class _Process(object):
  """Keeps the module load state of a single process."""
  def __init__(self):
    self._modules = {}

  def OnModuleLoaded(self, module):
    """Update module load state on a newly loaded module.

    Args:
      module: a _Module object for the newly loaded module.
    """
    self._modules[module.module_base] = module

  def OnModuleUnloaded(self, module_base):
    """Update module load state on a newly unloaded module.

    Args:
      module_base: the base address of a module that just unloaded.
    """
    self._modules.pop(module_base, None)

  def IsEmpty(self):
    """Check whether any modules are loaded.

    Returns:
      True iff no modules currently loaded in this process.
    """
    return not self._modules

  def FindModuleAt(self, addr):
    """Find the module loaded at a particular address in the process.

    Args:
      addr: an address within the process.

    Returns:
      A _Module object for the module at that address, or None if
      no such module.
    """
    for module in self._modules.itervalues():
      if (addr >= module.module_base and
          addr < module.module_base + module.module_size):
        return module

    return None


class ModuleDatabase(EventConsumer):
  """Keeps a database of the modules loaded in a process."""
  def __init__(self):
    EventConsumer.__init__(self)
    self._processes = {}

  def GetProcessModules(self, process_id):
    """Get all modules in a process.

    Args:
      process_id: the id of the process in question.

    Returns:
      a list of _Module objects, or None if no modules loaded in the process.
    """
    if process_id not in self._processes:
      return None

    return self._processes[process_id].values()

  def GetProcessModuleAt(self, process_id, addr):
    """Get the module loaded at a given address in a process.

    Args:
      process_id: the id of the process in question.
      addr: the address we're interested in.

    Returns:
      A _Module object for the found module, or None if no module
      is loaded at that address.
    """
    proc = self._processes.get(process_id)
    if proc:
      return proc.FindModuleAt(addr)

    return None

  @EventHandler(image.Event.DCStart, image.Event.Load)
  def _OnLoad(self, event):
    proc_id = event.process_id
    proc = self._processes.get(proc_id, None)
    if not proc:
      proc = _Process()
      self._processes[proc_id] = proc

    proc.OnModuleLoaded(_Module(event))

  @EventHandler(image.Event.UnLoad)
  def _OnUnLoad(self, event):
    proc = self._processes.get(event.process_id, None)
    if not proc:
      return

    proc.OnModuleUnloaded(event.ImageBase)
    if proc.IsEmpty():
      del self._processes[event.process_id]

  @EventHandler(process.Event.End)
  def _OnProcessEnd(self, event):
    # Clean up all modules on process termination.
    self._processes.pop(event.process_id, None)
