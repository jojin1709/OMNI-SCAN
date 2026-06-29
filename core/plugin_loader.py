class PluginLoader:
    def __init__(self):
        self.plugins = {}

    def load_plugins(self, plugin_dir):
        import importlib
        import os
        import sys
        if plugin_dir not in sys.path:
            sys.path.insert(0, plugin_dir)

    def register(self, name, cls):
        self.plugins[name] = cls

    def get(self, name):
        return self.plugins.get(name)