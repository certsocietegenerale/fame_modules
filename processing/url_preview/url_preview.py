# coding: utf-8

import os
from shutil import copyfile
from html.parser import HTMLParser

from fame.core.module import ProcessingModule, ModuleInitializationError
from fame.common.utils import tempdir

from ..docker_utils import HAVE_DOCKER, docker_client

class MyHTMLParser(HTMLParser):

    def __init__(self):
        HTMLParser.__init__(self)
        self._URLS = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for attr in attrs:
                if attr[0].lower() == "href" and (attr[1].lower().startswith("http") or attr[1].lower().startswith("ftp")):
                    self._URLS.append(attr[1])
        if tag == "form":
            for attr in attrs:
                if attr[0].lower() == "action" and (attr[1].lower().startswith("http") or attr[1].lower().startswith("ftp")):
                    self._URLS.append(attr[1])
        if tag == "meta":
            for attr in attrs:
                if attr[0].lower() == "http-equiv":
                    for att in attrs:
                        if att[0].lower() == "content":
                            url = att[1].split("=")
                            if len(url) > 1 and (url[1].lower().startswith("http") or url[1].lower().startswith("ftp")):
                                self._URLS.append(url[1])

    def get_urls(self):
        return self._URLS

class UrlPreview(ProcessingModule):

    name = 'url_preview'
    description = 'List all redirections from an URL request and take a screenshot'
    acts_on = ['url', 'html']

    config = [
        {
            'name': 'network_idle_timeout',
            'type': 'integer',
            'default': 500,
            'description': 'Specify the network idle timeout (ms)',
        }
    ]

    def initialize(self):
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")

        return True

    def save_preview(self, outdir):
        filepath = os.path.join(outdir, 'output.png')

        if os.path.isfile(filepath):
            self.add_support_file('preview', filepath)
            return True
        else:
            return False

    def preview(self, url):
        data_folder_path = os.path.dirname(self.outdir)
        volumes = {data_folder_path: {'bind': '/data', 'mode': 'rw'}}

        args = "node {} '{}' {}".format(
            '/script.js', url, self.network_idle_timeout)

        # start the right docker
        return docker_client.containers.run(
            'fame/url_preview',
            args,
            volumes=volumes,
            stderr=True,
            remove=True,
            working_dir=os.path.join("/data", data_folder_path)
        )

    def save_output(self, output):
        for line in output.splitlines():
            if line.startswith('redirect'):
                redirect = line.split()
                self.results['redirections'].append(redirect[1])
            else:
                self.log("debug", line)

        # add last element as target url
        # then delete last element
        self.results['target'] = self.results['redirections'].pop()

    def each_with_type(self, target, filetype):
        self.results = {
            'redirections': [],
            'target': None
        }

        # Create temporary directory to get results
        self.outdir = tempdir()

        if type(target) is bytes:
            target = target.decode("utf8")

        # Check if we're trying to analyze a local html file
        # if it is, the file is copied to the docker volume
        if filetype == "html":
            copyfile(target, os.path.join(self.outdir, "input.html"))
            target = "file:///data/input.html"

        # add http protocol if missing
        # requests lib needs it
        if filetype == "url" and not target.startswith('http'):
            target = 'http://{}'.format(target)

        if filetype == "url":
            self.add_ioc(target)

        # output dir
        results_dir = os.path.join(self.outdir, 'output')

        if not os.path.isdir(results_dir):
            os.mkdir(results_dir)

        # execute docker container
        output = self.preview(target)
        if type(output) is bytes:
            output = output.decode()

        # save log output from dockerized app, extract potential redirections
        self.save_output(output)

        # save preview image
        screenshot = self.save_preview(results_dir)

        with open(os.path.join(results_dir, "output.html")) as f:
            parser = MyHTMLParser()
            parser.feed(f.read())
            for url in parser.get_urls():
                self.add_ioc(url)

        if len(self.results['redirections']) > 0:
            # save redirections as observable
            self.add_ioc(self.results['redirections'], ['redirection'])

            # save target as observable
            self.add_ioc(self.results['target'])

        return len(self.results['redirections']) > 0 or screenshot
