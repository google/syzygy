#!python
# Copyright 2010 Google Inc.
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
from etw import TraceConsumer, EventHandler
from etw.descriptors import image
import os
import unittest


_SRC_DIR = os.path.abspath(os.path.join(__file__, '../../../../..'))

class TraceConsumerTest(unittest.TestCase):
  _TEST_LOG = os.path.normpath(
      os.path.join(_SRC_DIR,
                   'sawbuck/log_lib/test_data/image_data_32_v2.etl'))

  def testCreation(self):
    """Test creating a consumer."""
    consumer = TraceConsumer()

  def testOpenFileSession(self):
    """Test opening a file session."""
    consumer = TraceConsumer()
    consumer.OpenFileSession(self._TEST_LOG)

  def testConsume(self):
    """Test consuming a test log."""
    class TestConsumer(TraceConsumer):
      def __init__(self):
        super(TestConsumer, self).__init__()
        self._image_load_events = 0

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

    consumer = TestConsumer()
    consumer.OpenFileSession(self._TEST_LOG)
    consumer.Consume()
    self.assertNotEqual(consumer._image_load_events, 0)

  def testAdjacentConsumers(self):
    """Test two consumers defined in the same scope."""
    class TestConsumer1(TraceConsumer):
      def __init__(self):
        super(TestConsumer1, self).__init__()
        self._image_load_events = 0

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

    class TestConsumer2(TraceConsumer):
      def __init__(self):
        super(TestConsumer2, self).__init__()
        self._image_load_events = 0

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

    consumer1 = TestConsumer1()
    consumer2 = TestConsumer2()
    consumer1.OpenFileSession(self._TEST_LOG)
    consumer1.Consume()
    self.assertNotEqual(consumer1._image_load_events, 0)
    self.assertEqual(consumer2._image_load_events, 0)

  def testSubConsumers(self):
    """Test multi-level consumer hierarchy."""
    class TestConsumer(TraceConsumer):
      def __init__(self):
        super(TestConsumer, self).__init__()
        self._image_load_events = 0

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

    class SubTestConsumer(TestConsumer):
      pass

    consumer = SubTestConsumer()
    consumer.OpenFileSession(self._TEST_LOG)
    consumer.Consume()
    self.assertNotEqual(consumer._image_load_events, 0)

if __name__ == '__main__':
  unittest.main()
