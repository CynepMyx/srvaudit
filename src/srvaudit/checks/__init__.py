import importlib
import logging
import pkgutil

logger = logging.getLogger("srvaudit")

for _, name, _ in pkgutil.iter_modules(__path__):
    if not name.startswith("_"):
        try:
            importlib.import_module(f".{name}", __name__)
        except Exception as e:
            logger.warning(f"Failed to load check module '{name}': {e}")
