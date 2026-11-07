import yaml


def load(text: str) -> dict:
    return yaml.safe_load(text)
