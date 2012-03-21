#!python
# Copyright 2012 Google Inc.
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

import httplib
import json
from handler import metric
from model import client as client_db
from model import metric as metric_db
from model import product as product_db
from test.handler import handler_test

class MetricTest(handler_test.TestCase):

  def setUp(self):
    super(MetricTest, self).setUp()

    # Insert values into the db.
    p1 = product_db.Product(key_name='p1')
    p1.put()

    c1 = client_db.Client(key_name='c1', parent=p1, description='c1_desc')
    c1.put()

    m1 = metric_db.Metric(key_name='m1', parent=c1, description='m1_desc',
                          units='stones')
    m1.put()
    m2 = metric_db.Metric(key_name='m2', parent=c1, description='m2_desc',
                          units='furlongs')
    m2.put()

  def _InitHandler(self, input):
    self._handler = metric.MetricHandler()
    super(MetricTest, self)._InitHandler(self._handler, input)

  def testGetAll(self):
    self._InitHandler('')
    self._handler.get('p1', 'c1', '')
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'product_id': 'p1',
         'client_id': 'c1',
         'metrics': [
            {'metric_id': 'm1',
             'description': 'm1_desc',
             'units': 'stones'},
            {'metric_id': 'm2',
             'description': 'm2_desc',
             'units': 'furlongs'},
        ]},
        result)

  def testGetById(self):
    self._InitHandler('')
    self._handler.get('p1', 'c1', 'm1')
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'product_id': 'p1',
         'client_id': 'c1',
         'metric_id': 'm1',
         'description': 'm1_desc',
         'units': 'stones'},
        result)

  def testGetArgValidation(self):
    self._InitHandler('')
    self._handler.get('p2', 'c1', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('')
    self._handler.get('p1', 'c2', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('')
    self._handler.get('p1', 'c2', 'm3')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testPost(self):
    self._InitHandler('metric_id=m3&description=m3_desc&units=balls')
    self._handler.post('p1', 'c1', '')
    self.assertEqual(httplib.CREATED, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    c1 = client_db.Client.get_by_key_name('c1', p1)
    m3 = metric_db.Metric.get_by_key_name('m3', c1)
    self.assertTrue(m3 is not None)
    self.assertEqual('m3_desc', m3.description)
    self.assertEqual('balls', m3.units)

  def testPostArgValidation(self):
    self._InitHandler('metric_id=m3&description=m3_desc&units=balls')
    self._handler.post('p1', 'c1', 'm3')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('description=m3_desc&units=balls')
    self._handler.post('p1', 'c1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('metric_id=m3&units=balls')
    self._handler.post('p1', 'c1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('metric_id=m3&description=m3_desc')
    self._handler.post('p1', 'c1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('metric_id=m3&description=m3_desc&units=balls')
    self._handler.post('p2', 'c1', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('metric_id=m3&description=m3_desc&units=balls')
    self._handler.post('p1', 'c2', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('metric_id=m1&description=m1_desc&units=balls')
    self._handler.post('p1', 'c1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

  def testPut(self):
    self._InitHandler('description=new_m1_desc&units=borks')
    self._handler.put('p1', 'c1', 'm1')
    self.assertEqual(httplib.OK, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    c1 = client_db.Client.get_by_key_name('c1', p1)
    m1 = metric_db.Metric.get_by_key_name('m1', c1)
    self.assertEqual('new_m1_desc', m1.description)
    self.assertEqual('borks', m1.units)

  def testPutArgValidation(self):
    self._InitHandler('description=new_m1_desc&units=borks')
    self._handler.put('p1', 'c1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('description=new_m1_desc')
    self._handler.put('p1', 'c1', 'm1')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('units=borks')
    self._handler.put('p1', 'c1', 'm1')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('description=new_m1_desc&units=borks')
    self._handler.put('p2', 'c1', 'm1')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('description=new_m1_desc&units=borks')
    self._handler.put('p1', 'c2', 'm1')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('description=new_m1_desc&units=borks')
    self._handler.put('p1', 'c1', 'm3')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testDelete(self):
    self._InitHandler('')
    self._handler.delete('p1', 'c1', 'm1')
    self.assertEqual(httplib.OK, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    c1 = client_db.Client.get_by_key_name('c1', p1)
    self.assertTrue(metric_db.Metric.get_by_key_name('m1', c1) is None)

  def testDeleteArgValidation(self):
    self._InitHandler('')
    self._handler.delete('p1', 'c1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._InitHandler('')
    self._handler.delete('p2', 'c1', 'm1')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('')
    self._handler.delete('p1', 'c2', 'm1')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    self._InitHandler('')
    self._handler.delete('p1', 'c1', 'm3')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)
