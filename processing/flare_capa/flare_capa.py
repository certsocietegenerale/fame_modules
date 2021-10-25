from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError

try:
    import capa.main
    import capa.rules
    import capa.render.utils as rutils

    HAVE_CAPA = True
except ImportError:
    HAVE_CAPA = False

class FlareCapa(ProcessingModule):
    name = 'flare_capa'
    description = 'Analyze executable files using Flare Capa.'
    acts_on = ['executable']
    config = [
        {
            'name': 'rules',
            'type': 'str',
            'default': '/opt/capa/rules/',
            'description': 'Path for Capa rules.'
        }
    ]

    def initialize(self):
        if not HAVE_CAPA:
            raise ModuleInitializationError(self, 'Missing dependency: flare-capa')

    def each(self, target):
        self.results = {}

        try:
            rules = capa.rules.RuleSet(capa.main.get_rules(self.rules, disable_progress=True))
            extractor = capa.main.get_extractor(target, "auto", capa.main.BACKEND_VIV, [], False, disable_progress=True)
            capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        except Exception as error:
            raise ModuleExecutionError(self, 'Could not run capa on target with error: ' + str(error))

        meta = capa.main.collect_metadata('', target, self.rules, extractor)
        meta['analysis'].update(counts)
        doc = capa.render.result_document.convert_capabilities_to_result_document(meta, rules, capabilities)

        # extract all MBS behaviors
        # taken from https://github.com/mandiant/capa/blob/master/scripts/capa_as_library.py
        if doc:
            for rule in rutils.capability_rules(doc):
                if not rule['meta'].get('mbc'):
                    continue
                for mbc in rule['meta']['mbc']:
                    if mbc['objective'] not in self.results:
                        self.results[mbc['objective']] = []
                    self.results[mbc['objective']].append(f"{mbc['behavior']} {mbc.get('method')}::{mbc['id']}")
        return len(self.results) > 0
