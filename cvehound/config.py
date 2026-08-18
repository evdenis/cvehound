from collections.abc import Iterator, Mapping


class Config(Mapping[str, bool]):
    def __init__(self, config: str) -> None:
        enabled: dict[str, bool] = {}
        with open(config, encoding='utf8') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('CONFIG_'):
                    enabled[line.split('=')[0]] = True
                elif line.startswith('# CONFIG_') and line.endswith('is not set'):
                    enabled[line.split(' ')[1]] = False
        self._storage = enabled

    def __getitem__(self, key: str) -> bool:
        try:
            return self._storage[key]
        except KeyError:
            return False

    def __iter__(self) -> Iterator[str]:
        return iter(self._storage)

    def __len__(self) -> int:
        return len(self._storage)
