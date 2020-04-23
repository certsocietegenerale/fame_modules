import os
import sys
import json

"""
Todo:
    * Add json output as support_file
    * Snag that fancy domain graph off dnsdumpster?
    * Snag that fancy dns excel file off dnsdumpster?

"""

from fame.core.module import ProcessingModule
from fame.common.constants import VENDOR_ROOT
from fame.common.exceptions import ModuleInitializationError

try:
    sys.path.append(os.path.join(VENDOR_ROOT, 'dnsdmpstr'))
    import dnsdmpstr
    has_dnsdump = True
except ImportError:
    has_dnsdump = False

try:
    import tldextract
    has_tldextract = True
except ImportError:
    has_tldextract = False

class DnsDumpster(ProcessingModule):
    name = "dnsdumpster"
    description = "Enumerate domain DNS data."
    acts_on = ['url']

    config = [
        {
            'name': 'reverse_dns',
            'type': 'bool',
            'default': True,
            'description': 'List reverse DNS entries from DnsDumpster.'
        },
        {
            'name': 'page_links',
            'type': 'bool',
            'default': True,
            'description': 'Grab page links using HackerTarget.'
        },
        {
            'name': 'http_headers',
            'type': 'bool',
            'default': True,
            'description': 'Grab HTTP server headers from URL using HackerTarget.'
        },
    ]

    def initialize(self):
        if not has_dnsdump:
            raise ModuleInitializationError(self, "Missing dependancy: dnsdmpstr")
        if not has_tldextract:
            raise ModuleInitializationError(self, "Missing dependancy: tldextract")

    def each(self, target):
        self.results = {}

        # Get the root domain
        url = target
        domain = tldextract.extract(url)
        root_domain = domain.domain + '.' + domain.suffix

        # Initialize dnsdmpstr and enumerate the data
        dnsdump = dnsdmpstr.dnsdmpstr()

        # DNS Data
        self.log("debug", 'gathering dns data...')
        self.results['dns_data'] = dnsdump.dnslookup(root_domain)

        # Reverse DNS
        if self.reverse_dns:
            self.log("debug", 'gathering reverse dns data...')
            self.results['reverse_dns'] = dnsdump.reversedns(root_domain)

        # HTTP Headers
        if self.http_headers:
            self.log("debug", 'gathering url headers...')
            # Query HackerTarget with a cleaned up target URL
            dest = url.split('?')[0]  # reduce dnsdmpstr errors
            dest = dest.split('#')[0] # 
            headers = dnsdump.httpheaders(dest)
            if not "error" in headers:
                self.results['headers'] = headers

        # Page Links
        if self.page_links:
            self.log("debug", 'gathering url links...')
            # Query HackerTarget with a cleaned up target URL
            dest = url.split('?')[0]  # reduce dnsdmpstr errors
            dest = dest.split('#')[0] #
            links = dnsdump.pagelinks(dest)
            if not "url is invalid" in links:
                self.results['links'] = links

        return True