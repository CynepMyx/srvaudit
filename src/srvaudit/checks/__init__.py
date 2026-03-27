import importlib
import pkgutil

for _, name, _ in pkgutil.iter_modules(__path__):
    if not name.startswith("_"):
        importlib.import_module(f".{name}", __name__)
