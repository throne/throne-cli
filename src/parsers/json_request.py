# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY


# Import Third Party Modules
import json
import urllib3
import sys
import logging
# Import Throne Modules
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError)

# Set log variable for verbose output
log = logging.getLogger(__name__)

# Set python check interval to 1, hopefully to improve performance
sys.setswitchinterval(1)

class _JSONRequest():
    # This class is used to get JSON data from a specified URL.
    def __init__(self):
        self.http = urllib3.PoolManager()
    # This function is what actually gets the URL data.
    def get_json(self, url=None):
        conn = self.http.request('GET', url)
        data = conn.data
        # Only return JSON data if we get a HTTP Status Code: 200 OK
        if conn.status == 200:
            log.debug(f"Received HTTP/200 from {url}, loading JSON data...")
            d = json.loads(data.decode('utf-8', 'ignore'))
            return d
        else:
            # Raise an HTTP error if response isn't 200 OK
            log.debug(f"Received HTTP/{conn.status} from {url}...raising exception")
            raise ThroneHTTPError(f"{conn.status}\n{url}")