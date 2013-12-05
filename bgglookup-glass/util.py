# Copyright (C) 2013 Google Inc.
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

"""Utility functions for the Quickstart."""

__author__ = 'alainv@google.com (Alain Vongsouvanh)'


from urlparse import urlparse
from StringIO import StringIO

import httplib2, gzip, urllib2, urlparse

from apiclient.discovery import build
from oauth2client.appengine import StorageByKeyName
import sessions

from model import Credentials


# Load the secret that is used for client side sessions
# Create one of these for yourself with, for example:
# python -c "import os; print os.urandom(64)" > session.secret
SESSION_SECRET = open('session.secret').read()
USER_AGENT = 'OpenAnything/1.0 +http://diveintopython.org/http_web_services/'


def get_full_url(request_handler, path):
  """Return the full url from the provided request handler and path."""
  pr = urlparse(request_handler.request.url)
  return '%s://%s%s' % (pr.scheme, pr.netloc, path)


def load_session_credentials(request_handler):
  """Load credentials from the current session."""
  session = sessions.LilCookies(request_handler, SESSION_SECRET)
  userid = session.get_secure_cookie(name='userid')
  if userid:
    return userid, StorageByKeyName(Credentials, userid, 'credentials').get()
  else:
    return None, None


def store_userid(request_handler, userid):
  """Store current user's ID in session."""
  session = sessions.LilCookies(request_handler, SESSION_SECRET)
  session.set_secure_cookie(name='userid', value=userid)


def create_service(service, version, creds=None):
  """Create a Google API service.

  Load an API service from a discovery document and authorize it with the
  provided credentials.

  Args:
    service: Service name (e.g 'mirror', 'oauth2').
    version: Service version (e.g 'v1').
    creds: Credentials used to authorize service.
  Returns:
    Authorized Google API service.
  """
  # Instantiate an Http instance
  http = httplib2.Http()

  if creds:
    # Authorize the Http instance with the passed credentials
    creds.authorize(http)

  return build(service, version, http=http)


def auth_required(handler_method):
  """A decorator to require that the user has authorized the Glassware."""

  def check_auth(self, *args):
    self.userid, self.credentials = load_session_credentials(self)
    self.mirror_service = create_service('mirror', 'v1', self.credentials)
    # TODO: Also check that credentials are still valid.
    if not self.credentials:
      self.redirect('/auth')
      return
    else:
      handler_method(self, *args)
  return check_auth

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):    
    def http_error_301(self, req, fp, code, msg, headers):  
        result = urllib2.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers)              
        result.status = code                                
        return result                                       

    def http_error_302(self, req, fp, code, msg, headers):  
        result = urllib2.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)              
        result.status = code                                
        return result                                       

class DefaultErrorHandler(urllib2.HTTPDefaultErrorHandler):   
    def http_error_default(self, req, fp, code, msg, headers):
        result = urllib2.HTTPError(                           
            req.get_full_url(), code, msg, headers, fp)       
        result.status = code                                  
        return result                                         

def openAnything(source, etag=None, lastmodified=None, agent=USER_AGENT):
    '''URL, filename, or string --> stream

    This function lets you define parsers that take any input source
    (URL, pathname to local or network file, or actual data as a string)
    and deal with it in a uniform manner.  Returned object is guaranteed
    to have all the basic stdio read methods (read, readline, readlines).
    Just .close() the object when you're done with it.

    If the etag argument is supplied, it will be used as the value of an
    If-None-Match request header.

    If the lastmodified argument is supplied, it must be a formatted
    date/time string in GMT (as returned in the Last-Modified header of
    a previous request).  The formatted date/time will be used
    as the value of an If-Modified-Since request header.

    If the agent argument is supplied, it will be used as the value of a
    User-Agent request header.
    '''

    if hasattr(source, 'read'):
        return source

    if source == '-':
        return sys.stdin

    if urlparse.urlparse(source)[0] == 'http':                                      
        # open URL with urllib2                                                     
        request = urllib2.Request(source)                                           
        request.add_header('User-Agent', agent)                                     
        if etag:                                                                    
            request.add_header('If-None-Match', etag)                               
        if lastmodified:                                                            
            request.add_header('If-Modified-Since', lastmodified)                   
        request.add_header('Accept-encoding', 'gzip')                               
        opener = urllib2.build_opener(SmartRedirectHandler(), DefaultErrorHandler())
        return opener.open(request)                                                 
    
    # try to open with native open function (if source is a filename)
    try:
        return open(source)
    except (IOError, OSError):
        pass

    # treat source as string
    return StringIO(str(source))
    
    
def fetch(source, etag=None, last_modified=None, agent=USER_AGENT):  
    '''Fetch data and metadata from a URL, file, stream, or string'''
    result = {}                                                      
    f = openAnything(source, etag, last_modified, agent)             
    result['data'] = f.read()                                        
    if hasattr(f, 'headers'):                                        
        # save ETag, if the server sent one                          
        result['etag'] = f.headers.get('ETag')                       
        # save Last-Modified header, if the server sent one          
        result['lastmodified'] = f.headers.get('Last-Modified')      
        if f.headers.get('content-encoding', '') == 'gzip':          
            # data came back gzip-compressed, decompress it          
            result['data'] = gzip.GzipFile(fileobj=StringIO(result['data'])).read()
    if hasattr(f, 'url'):                                            
        result['url'] = f.url                                        
        result['status'] = 200                                       
    if hasattr(f, 'status'):                                         
        result['status'] = f.status                                  
    f.close()                                                        
    return result      
