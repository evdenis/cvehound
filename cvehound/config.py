class Config:

    def __init__(self, config):
        enabled = []
        disabled = []
        with open(config, 'rt', encoding='utf8') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('CONFIG_'):
                    enabled.append(line.split('=')[0])
                elif line.startswith('# CONFIG_') and line.endswith('is not set'):
                    disabled.append(line.split(' ')[1])
        self.cfg_enabled = enabled
        self.cfg_disabled = disabled

    def enabled(self, opt):
        return opt in self.cfg_enabled

    def disabled(self, opt):
        return opt not in self.cfg_enabled
