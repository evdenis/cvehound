
class UnsupportedVersion(Exception):
    def __init__(self, spatch_version, cve, rule_version):
        self.spatch_version = '.'.join(str(spatch_version))
        self.cve = cve
        self.rule_version = '.'.join(str(rule_version))

