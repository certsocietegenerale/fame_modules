# coding: utf-8

import os

from fame.core.module import ProcessingModule, ModuleInitializationError
from fame.common.utils import tempdir

from ..docker_utils import HAVE_DOCKER, docker_client


class UrlPreview(ProcessingModule):

    name = 'url_preview'
    description = 'List all redirections from an URL request and take a screenshot'
    acts_on = ['url']

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
        args = 'node {} {} {}'.format(
            '/script.js', url, self.network_idle_timeout)

        # start the right docker
        return docker_client.containers.run(
            'fame/url_preview',
            args,
            volumes={self.outdir: {'bind': '/data', 'mode': 'rw'}},
            stderr=True,
            remove=True
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

    def each(self, target):
        self.results = {
            'redirections': [],
            'target': None
        }

        # add http protocol if missing
        # requests lib needs it
        if not target.startswith('http'):
            target = 'http://{}'.format(target)

        # Create temporary directory to get results
        self.outdir = tempdir()

        # output dir
        results_dir = os.path.join(self.outdir, 'output')

        if not os.path.isdir(results_dir):
            os.mkdir(results_dir)

        # execute docker container
        output = self.preview(target)

        # save log output from dockerized app, extract potential redirections
        self.save_output(output)

        # save preview image
        screenshot = self.save_preview(results_dir)

        if len(self.results['redirections']) > 0:
            # save redirections as observable
            self.add_ioc(self.results['redirections'], ['redirection'])

            # save target as observable
            self.add_ioc(self.results['target'])

        return len(self.results['redirections']) > 0 or screenshot
