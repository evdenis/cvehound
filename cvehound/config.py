from collections.abc import Mapping

class Config(Mapping):

    def __init__(self, config):
        enabled = {}
        with open(config, 'rt', encoding='utf8') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('CONFIG_'):
                    enabled[line.split('=')[0]] = True
                elif line.startswith('# CONFIG_') and line.endswith('is not set'):
                    enabled[line.split(' ')[1]] = False
        self._storage = enabled

    def __getitem__(self, key):
        try:
            self._storage[key]
        except Exceptions:
            return False

    def __iter__(self):
        return iter(self._storage)

    def __len__(self):
        return len(self._storage)

    def get_mapping(self):
        return self._storage
