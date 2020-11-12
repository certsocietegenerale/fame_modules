# coding: utf-8

import os
import re

from fame.core.module import ProcessingModule, ModuleInitializationError
from ..docker_utils import temp_volume, HAVE_DOCKER, docker_client


def atoi(text):
    return int(text) if text.isdigit() else text


# Correctly sort pages
def natural_keys(text):
    return [atoi(c) for c in re.split('(\d+)', text)]


class DocumentPreview(ProcessingModule):

    name = 'document_preview'
    description = 'Display pages of pdf and office files'
    acts_on = ['pdf', 'word', 'powerpoint', 'excel', 'rtf']

    config = [
        {
            'name': 'max_pages',
            'type': 'integer',
            'default': 5,
            'description': 'Specify the maximum number of pages to display',
        }
    ]

    def initialize(self):
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")

        return True

    def save_output(self, output):
        self.log("debug", output)

    def save_images(self, directory):
        extracted_images = False

        # get all images, sorted by page number
        image_files = os.listdir(directory)
        image_files.sort(key=natural_keys)

        for filename in image_files:
            if filename.endswith('.jpeg'):
                # extract page number from filename
                number = filename.split('_')[-1].split('.')[0]
                self.add_support_file('page_#{}'.format(number), os.path.join(directory, filename))
                extracted_images = True

        return extracted_images

    def preview(self, target, target_type):
        target = os.path.join(
            os.path.basename(self.outdir),
            os.path.basename(target)
        )

        data_folder_path = os.path.dirname(self.outdir)
        volumes = {data_folder_path: {'bind': '/data', 'mode': 'rw'}}

        args = "--target \"{}\" --target_type {} --max_pages {}".format(
            target, target_type, self.max_pages)

        # start the right docker
        return docker_client.containers.run(
            'fame/document_preview',
            args,
            volumes=volumes,
            stderr=True,
            remove=True
        )

    def each_with_type(self, target, target_type):
        self.results = ""

        # Create temporary directory to get results
        self.outdir = temp_volume(target)

        # Execute pre-viewing on target
        output = self.preview(target, target_type)
        if type(output) is bytes:
            output = output.decode()

        # save log output from dockerized app
        self.save_output(output)

        # output dir
        results_dir = os.path.join(self.outdir, 'output')

        # save images and return boolean
        return self.save_images(results_dir)
