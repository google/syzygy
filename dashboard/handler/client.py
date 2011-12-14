# Copyright 2011 Google Inc.
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
from google.appengine.ext import db
from google.appengine.ext import webapp
from model import client as client_db

class ClientHandler(webapp.RequestHandler):
  """A class to handle creating and querying clients."""

  def get(self, client_id):
    """Responds with information about clients.

    If no client_id is specified, a list of available clients is returned.
    If a client_id is specified, information about that client is returned.

    Args:
      client_id: The client ID. May be an empty string.
    """
    self.response.headers['Content-Type'] = 'application/json'

    if client_id:
      client = client_db.Client.get_by_key_name(client_id)
      if not client:
        self.error(404)  # Not found.
        return

      data = {'id': client.key().id_or_name(),
              'description': client.description}
    else:
      clients = client_db.Client.all()

      data = []
      for client in clients:
        data.append({'id': client.key().id_or_name(),
                     'description': client.description})

    json.dump(data, self.response.out)

  def post(self, _):
    """Creates a new client.

    Adds a client to the data store. The ID and description should be specified
    in the body of the request. The response is 'OK' on success or an error
    message on failure.
    """
    id = self.request.get('id', None)
    desc = self.request.get('description', None)
    if not id or not desc:
      self.error(400)  # Bad request.
      return

    # Creates a new client or updates the description for an existing client.
    client = client_db.Client(key_name=id, description=db.Text(desc))
    client.put()
