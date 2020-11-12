# coding: utf-8

import re
import email.Header
from email.parser import HeaderParser

try:
    import dateutil.parser
    from dateutil import tz, relativedelta
    HAVE_DATEUTIL = True
except ImportError:
    HAVE_DATEUTIL = False


from fame.core.module import ProcessingModule, ModuleInitializationError


def decode_mime_words(s):
    if s:
        return ''.join(
            word.decode(encoding or 'utf8') if isinstance(word, bytes) else word
            for word, encoding in email.Header.decode_header(s))
    else:
        return ''


def list_config(string):
    """Convert a comma-separated list in a python list"""
    return [element.strip().lower() for element in string.split(',') if element.strip()]


class EmailHeader(ProcessingModule):

    name = 'email_headers'
    description = 'Email Headers Parser'
    acts_on = ['email_headers']

    config = [
        {
            'name': 'highlight',
            'type': 'string',
            'default': 'authentication-results, received-spf, dkim-signature, x-originating-ip, arc-authentication-results',
            'description': 'Specify the header entries you want to highlight (comma-separated)',
        },
        {
            'name': 'dkim_headers',
            'type': 'string',
            'default': 'authentication-results, arc-authentication-results',
            'description': 'Specify the header entries to use for DKIM check (comma-separated)',
        },
        {
            'name': 'dmarc_headers',
            'type': 'string',
            'default': 'authentication-results, arc-authentication-results',
            'description': 'Specify the header entries to use for DMARC check (comma-separated)',
        },
        {
            'name': 'spf_headers',
            'type': 'string',
            'default': 'authentication-results, arc-authentication-results',
            'description': 'Specify the header entries to use for SPF check (comma-separated)',
        }
    ]

    def initialize(self):
        if not HAVE_DATEUTIL:
            raise ModuleInitializationError(self, "Missing dependency: python-dateutil")

        self.highlight = list_config(self.highlight)
        self.dkim_headers = list_config(self.dkim_headers)
        self.dmarc_headers = list_config(self.dmarc_headers)
        self.spf_headers = list_config(self.spf_headers)

    def delay_to_string(self, delay):
        string = ''
        if delay.minutes:
            string = '{} min '.format(delay.minutes)
        if delay.seconds:
            string = string + '{} sec'.format(delay.seconds)

        return string

    # This code is originally from https://github.com/lnxg33k/MHA
    def parse_date(self, line):
        try:
            r = dateutil.parser.parse(line, fuzzy=True)
            r = r.astimezone(tz.tzutc())
        # if the fuzzy parser failed to parse the line due to
        # incorrect timezone information issue 5 GitHub
        except ValueError:
            r = re.findall('^(.*?)\s*\(', line)
            if r:
                r = dateutil.parser.parse(r[0])
        return r

    # This code is originally from https://github.com/lnxg33k/MHA
    def parse_received(self, received):
        timeline = []
        last_timestamp = []
        if received:
            index = len(received)
            for i in range(len(received)):
                if ';' in received[i]:
                    line = received[i].split(';')
                else:
                    line = received[i].split('\r\n')
                line = list(map(str.strip, line))
                line = [x.replace('\r\n', '') for x in line]

                org_time = self.parse_date(line[1])

                if line[0].startswith('from'):
                    data = re.findall(
                        """
                        from\s+
                        (.*?)\s+
                        by(.*?)
                        (?:
                            (?:with|via)
                            (.*?)
                            (?:id|$)
                            |id|$
                        )""", line[0], re.DOTALL | re.X)
                else:
                    data = re.findall(
                        """
                        ()by
                        (.*?)
                        (?:
                            (?:with|via)
                            (.*?)
                            (?:id|$)
                            |id
                        )""", line[0], re.DOTALL | re.X)

                data = [x.replace('\n', ' ') for x in list(map(str.strip, data[0]))]
                timeline = [{
                    'order': str(index-1),
                    'delay': '',
                    'from': data[0],
                    'to': data[1],
                    'protocol': data[2],
                    'timestamp': org_time.strftime('%m/%d/%Y %I:%M:%S %p')
                }] + timeline

                if last_timestamp:
                    timeline[1]['delay'] = self.delay_to_string(relativedelta.relativedelta(last_timestamp, org_time))
                last_timestamp = org_time
                index -= 1

        return timeline

    def authentication_results(self, headers, headers_to_check, regex):
        results = {}

        for header, value in headers:
            if header.lower() in headers_to_check:
                match = regex.search(value.lower())
                if match:
                    status = match.group(1)
                    domain = match.group(2)

                    if (domain not in results) or ('fail' in results[domain]):
                        results[domain] = status

        return results

    def parse_dmarc(self, headers):
        dmarc_re = re.compile(r'dmarc=([^ ;]+)[^;]+header.from=([^ ;]+)')

        return self.authentication_results(headers, self.dmarc_headers, dmarc_re)

    def parse_dkim(self, headers):
        dkim_re = re.compile(r'dkim=([^ ;]+)[^;]+header.i=([^ ;]+)')

        return self.authentication_results(headers, self.dkim_headers, dkim_re)

    def parse_spf(self, headers):
        spf_re = re.compile(r'spf=([^ ;]+)[^;@]+(@[^ ;]+)')

        return self.authentication_results(headers, self.spf_headers, spf_re)

    def each(self, target):
        self.results = {}

        header_raw = open(target, 'r').read()
        header = HeaderParser()
        parsed_headers = header.parsestr(header_raw)

        # Get Useful Headers
        self.results['From'] = decode_mime_words(parsed_headers['From'])
        self.results['ReturnPath'] = decode_mime_words(parsed_headers['Return-Path'])
        self.results['ReplyTo'] = decode_mime_words(parsed_headers['Reply-To'])
        self.results['To'] = decode_mime_words(parsed_headers['To'])
        self.results['Subject'] = decode_mime_words(parsed_headers['Subject'])
        self.results['Date'] = parsed_headers['Date']
        self.results['Cc'] = decode_mime_words(parsed_headers['Cc'])

        # Parse Received and Authentication Headers
        self.results['Received'] = self.parse_received(parsed_headers.get_all('Received'))
        self.results['DKIM'] = self.parse_dkim(list(parsed_headers.items()))
        self.results['SPF'] = self.parse_spf(list(parsed_headers.items()))
        self.results['DMARC'] = self.parse_dmarc(list(parsed_headers.items()))

        self.results['headers'] = list(parsed_headers.items())
        self.results['highlight'] = self.highlight

        return True
