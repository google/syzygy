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

import json
import urlparse
from google.appengine.ext import webapp
from model import client as client_db
from model import metric as metric_db
from model import product as product_db


class MetricHandler(webapp.RequestHandler):
  """A class to handle creating, reading, updating and deleting metrics.

  Handles GET, POST, PUT and DELETE requests for /metrics/<product>/<client>/
  and /metrics/<product>/<client>/<metric>. All functions have the same
  signature, even though they may not use all parameters, so that a single route
  can be used for the handler.
  """

  def get(self, product_id, client_id, metric_id):
    """Responds with information about all metrics or a specific metric.

    /metrics/<product>/<client>
      Responds with a JSON encoded object that contains a list of metric IDs for
      the given product and client
    /metrics/<product>/<client>/<metric>
      Responds with a JSON encoded object of the product ID, client ID, metric
      ID, description and units for the given product, client and metric.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. May be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(404)  # Not found.
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(404)  # Not found.
      return

    if not metric_id:
      metric_keys = metric_db.Metric.all(keys_only=True)
      metric_keys.ancestor(client)
      metric_ids = [key.name() for key in metric_keys]

      result = {'product_id': product.key().name(),
                'client_id': client.key().name(),
                'metric_ids': metric_ids}
    else:
      metric = metric_db.Metric.get_by_key_name(metric_id, client)
      if not metric:
        self.error(404)  # Not found.
        return

      result = {'product_id': product.key().name(),
                'client_id': client.key().name(),
                'metric_id': metric.key().name(),
                'description': metric.description,
                'units': metric.units}

    self.response.headers['Content-Type'] = 'application/json'
    json.dump(result, self.response.out)

  def post(self, product_id, client_id, metric_id):
    """Creates a new metric.

    /metrics/<product>/<client>
      Creates a new metric. The metric ID, description and units should be
      specified in the body of the request.
    /metrics/<product>/<client>/<metric>
      Unused.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. Must be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(404)  # Not found.
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(404)  # Not found.
      return

    if metric_id:
      self.error(400)  # Bad request.
      return
    
    metric_id = self.request.get('metric_id', None)
    description = self.request.get('description', None)
    units = self.request.get('units', None)
    if not metric_id or not description or not units:
      self.error(400)  # Bad request.
      return

    # Make sure that this metric ID doesn't already exist.
    metric = metric_db.Metric.get_by_key_name(metric_id, client)
    if metric:
      self.error(400)  # Bad request.
      return

    # Creates a new metric.
    metric = metric_db.Metric(key_name=metric_id, parent=client,
                              description=description, units=units)
    metric.put()

  def put(self, product_id, client_id, metric_id):
    """Updates a metric.

    /metrics/<product>/<client>
      Unused.
    /metrics/<product>/<client>/<metric>
      Updates a metric. The description and units should be specified in the
      body of the request.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. Must not be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(404)  # Not found.
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(404)  # Not found.
      return

    if not metric_id:
      self.error(400)  # Bad request.
      return

    # Make sure that this metric ID already exists.
    if not metric_db.Metric.get_by_key_name(metric_id, client):
      self.error(400)  # Bad request.
      return

    # Appengine bug: parameters in body aren't parsed for PUT requests.
    # http://code.google.com/p/googleappengine/issues/detail?id=170
    params = urlparse.parse_qs(self.request.body)
    description = params.get('description', [None])[0]
    units = params.get('units', [None])[0]
    if not description or not units:
      self.error(400)  # Bad request.
      return

    # Update the metric.
    metric = metric_db.Metric(key_name=metric_id, parent=client,
                              description=description, units=units)
    metric.put()

  def delete(self, product_id, client_id, metric_id):
    """Deletes a metric.

    /metrics/<product>/<client>
      Unused.
    /metrics/<product>/<client>/<metric>
      Deletes the specified metric.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. Must not be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(404)  # Not found.
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(404)  # Not found.
      return

    if not metric_id:
      self.error(400)  # Bad request.
      return

    # Delete the metric.
    metric = metric_db.Metric.get_by_key_name(metric_id, client)
    if not metric:
      self.error(400)  # Bad request.
      return

    metric.delete()
