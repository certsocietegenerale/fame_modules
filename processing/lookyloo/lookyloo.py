# coding: utf-8

from html.parser import HTMLParser

from fame.core.module import ProcessingModule, ModuleInitializationError
from fame.common.utils import tempdir

import time, os

from urllib.parse import urlparse
import re

try:
    import pylookyloo
    HAVE_LOOKYLOO = True
    print('Lookyloo imported')
except ImportError:
    HAVE_LOOKYLOO = False
    print('Lookyloo not found')

class MyHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self._URLS = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for attr in attrs:
                if attr[0].lower() == "href" and (
                    attr[1].lower().startswith("http") or attr[1].lower().startswith("ftp")
                ):
                    self._URLS.append(attr[1])
        if tag == "form":
            for attr in attrs:
                if attr[0].lower() == "action" and (
                    attr[1].lower().startswith("http") or attr[1].lower().startswith("ftp")
                ):
                    self._URLS.append(attr[1])
        if tag == "meta":
            for attr in attrs:
                if attr[0].lower() == "http-equiv":
                    for att in attrs:
                        if att[0].lower() == "content":
                            url = att[1].split("=")
                            if len(url) > 1 and (
                                url[1].lower().startswith("http")
                                or url[1].lower().startswith("ftp")
                            ):
                                self._URLS.append(url[1])

    def get_urls(self):
        return self._URLS


class Lookyloo(ProcessingModule):

    name = "lookyloo"
    description = "List all redirections from an URL request and take a screenshot"
    acts_on = ["url"]

    config = [
        {
            "name": "blur_level",
            "type": "integer",
            "default": 4,
            "description": "Specify the amount of blurring (in pixels)",
        },
        {
            "name": "instance",
            "type": "str",
            "default": "https://lookyloo.circl.lu",
            "description": "URL of the instance",
        }
        ,
        {
            "name": "safe_domains",
            "type": "text",
            "description": "Specify the domains that are considered safe and must not be analysed (one domain per line)",
        }
    ]

    def initialize(self):
        if not HAVE_LOOKYLOO:
            raise ModuleInitializationError(self, "Missing dependency: pylookyloo")

        return True

    def each(self, target):

        # add http protocol if missing
        # requests lib needs it
        if not target.startswith("http"):
            target = "http://{}".format(target)

        o = urlparse(target)

        if self.safe_domains is not None:
            for safe_domain in self.safe_domains.split('\n'):
                if re.match(".*\." + safe_domain.strip().lower() ,o.hostname):
                    self.log("info", "You must not analyze this domain. Did you read the documentation?")
                    return False

        myinstance = pylookyloo.Lookyloo(self.instance)

        self.results = {"redirections": [], "target": None}

        if myinstance.is_up:
            uuid = myinstance.enqueue(target, listing=False,quiet=True, Depth=10)
        else:
            self.log("error", "Lookyloo backend at '{0}' is unavailable.".format(self.instance))
            return False

        status = 0
        tries = 0
        while (status == 0 or status == 2) and tries < 10 :
            time.sleep(5)
            status = myinstance.get_status(uuid)["status_code"]
            tries = tries + 1

        if status != 1:
            self.log("error", "Unable to capture '{0}', probably timed out.".format(target))
            return False

        redirects = myinstance.get_redirects(uuid)

        for redirect in redirects["response"]["redirects"]:
            self.results["redirections"].append(redirect)

        self.results["target"] = redirects["response"]["redirects"][-1]

        screenshot = myinstance.get_screenshot(uuid)

        # Create temporary directory
        self.outdir = tempdir()
        # output dir
        results_dir = os.path.join(self.outdir, "output")
        if not os.path.isdir(results_dir):
            os.mkdir(results_dir)

        filepath = os.path.join(results_dir, "output.png")

        with open(filepath, "wb") as screenshot_file:
        # Write bytes to file
            screenshot_file.write(screenshot.getbuffer())

        if os.path.exists(filepath) and os.path.isfile(filepath):
            self.add_support_file("preview", filepath)

        raw_html = myinstance.get_html(uuid)

        parser = MyHTMLParser()
        parser.feed(raw_html.getvalue())
        for url in parser.get_urls():
            self.add_ioc(url)

        if len(self.results["redirections"]) > 0:
            # save redirections and target as observable
            self.add_ioc(self.results["redirections"], ["redirection"])

        return True
