"""
Plugin System - Allow custom scanning and exploitation modules.
Users can add their own tools and methodologies without modifying core code.
"""
import os
import importlib.util
from typing import Dict, List, Any, Callable
from dataclasses import dataclass


@dataclass
class Plugin:
    """A registered plugin."""
    name: str
    description: str
    version: str = "1.0.0"
    scan_function: Callable = None
    exploit_function: Callable = None
    author: str = "unknown"


class PluginManager:
    """Manage custom plugins for BlacksmithAI."""

    def __init__(self, plugins_dir: str = "./plugins"):
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, Plugin] = {}
        os.makedirs(plugins_dir, exist_ok=True)
        self.load_all_plugins()

    def load_plugin(self, filepath: str) -> bool:
        """Load a plugin from a Python file."""
        try:
            spec = importlib.util.spec_from_file_location("plugin", filepath)
            if not spec or not spec.loader:
                return False

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Check if module has required attributes
            if not hasattr(module, "PLUGIN_NAME"):
                return False

            plugin = Plugin(
                name=getattr(module, "PLUGIN_NAME", "unnamed"),
                description=getattr(module, "PLUGIN_DESCRIPTION", ""),
                version=getattr(module, "PLUGIN_VERSION", "1.0.0"),
                author=getattr(module, "PLUGIN_AUTHOR", "unknown"),
                scan_function=getattr(module, "scan", None),
                exploit_function=getattr(module, "exploit", None),
            )

            self.plugins[plugin.name] = plugin
            print(f"[Plugin] Loaded: {plugin.name} v{plugin.version}")
            return True

        except Exception as e:
            print(f"[Plugin] Failed to load {filepath}: {e}")
            return False

    def load_all_plugins(self):
        """Load all plugins from the plugins directory."""
        if not os.path.exists(self.plugins_dir):
            return

        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                filepath = os.path.join(self.plugins_dir, filename)
                self.load_plugin(filepath)

    def run_scan(self, plugin_name: str, target: str) -> Any:
        """Run a plugin's scan function."""
        plugin = self.plugins.get(plugin_name)
        if not plugin or not plugin.scan_function:
            return {"error": f"Plugin {plugin_name} not found or no scan function"}

        try:
            return plugin.scan_function(target)
        except Exception as e:
            return {"error": str(e)}

    def run_exploit(self, plugin_name: str, target: str, **kwargs) -> Any:
        """Run a plugin's exploit function."""
        plugin = self.plugins.get(plugin_name)
        if not plugin or not plugin.exploit_function:
            return {"error": f"Plugin {plugin_name} not found or no exploit function"}

        try:
            return plugin.exploit_function(target, **kwargs)
        except Exception as e:
            return {"error": str(e)}

    def list_plugins(self) -> List[Dict[str, str]]:
        """List all loaded plugins."""
        return [
            {
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "author": p.author,
            }
            for p in self.plugins.values()
        ]

    def create_example_plugin(self, name: str) -> str:
        """Create an example plugin template."""
        template = f'''"""
{name} - Custom plugin for BlacksmithAI
"""

PLUGIN_NAME = "{name}"
PLUGIN_DESCRIPTION = "Custom scanning plugin"
PLUGIN_VERSION = "1.0.0"
PLUGIN_AUTHOR = "your_name"


def scan(target: str):
    """Custom scan function."""
    return {{"target": target, "result": "example scan result"}}


def exploit(target: str, **kwargs):
    """Custom exploit function."""
    return {{"target": target, "result": "example exploit result"}}
'''
        filepath = os.path.join(self.plugins_dir, f"{name}.py")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(template)
        return filepath


# Global instance
plugin_manager = PluginManager()
