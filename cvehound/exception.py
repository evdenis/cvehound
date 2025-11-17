
class UnsupportedVersion(Exception):
    def __init__(self, spatch_version, cve, rule_version):
        # Convert version integer (e.g., 107) to dotted string (e.g., "1.0.7")
        # Version encoding: XYZ represents version X.Y.Z
        self.spatch_version = f"{spatch_version // 100}.{(spatch_version // 10) % 10}.{spatch_version % 10}"
        self.cve = cve
        self.rule_version = f"{rule_version // 100}.{(rule_version // 10) % 10}.{rule_version % 10}"

