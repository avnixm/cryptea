"""
Dynamic Module Loader for Cryptea
Provides lazy loading and unloading of tool modules to minimize memory footprint.
"""

from __future__ import annotations

import gc
import importlib
import sys
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Type

from .logger import configure_logging

_LOG = configure_logging()


@dataclass
class ModuleInfo:
    """Information about a loaded module."""

    name: str
    module: Any
    loaded_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    size_estimate: int = 0  # Rough memory estimate
    
    def mark_accessed(self) -> None:
        """Mark module as accessed."""
        self.last_accessed = time.time()
        self.access_count += 1
    
    @property
    def idle_time(self) -> float:
        """Time since last access in seconds."""
        return time.time() - self.last_accessed


class ModuleLoader:
    """
    Lazy module loader with automatic unloading.
    
    Features:
    - Loads modules on-demand
    - Tracks module usage
    - Automatically unloads idle modules
    - Forces garbage collection after unload
    - Provides memory usage estimates
    """

    def __init__(self, *, idle_timeout: float = 600.0) -> None:
        """
        Initialize the module loader.
        
        Args:
            idle_timeout: Seconds of inactivity before auto-unload (default 10 minutes)
        """
        self.modules: Dict[str, ModuleInfo] = {}
        self.idle_timeout = idle_timeout
        self._cache: Dict[str, weakref.ref] = {}
        
        _LOG.info(f"ModuleLoader initialized with {idle_timeout}s idle timeout")
    
    def load_tool(
        self,
        category: str,
        tool_name: str,
        *,
        force_reload: bool = False
    ) -> Any:
        """
        Load a tool module dynamically.
        
        Args:
            category: Tool category (e.g., 'crypto', 'forensics')
            tool_name: Name of the tool module
            force_reload: Force reload even if cached
        
        Returns:
            The loaded module or tool class
        """
        module_path = f"ctf_helper.modules.{category}.{tool_name}"
        
        # Check if already loaded
        if module_path in self.modules and not force_reload:
            mod_info = self.modules[module_path]
            mod_info.mark_accessed()
            _LOG.debug(f"Using cached module: {module_path}")
            return mod_info.module
        
        # Load the module
        try:
            _LOG.info(f"Loading module: {module_path}")
            module = importlib.import_module(module_path)
            
            # Try to find the tool class
            tool_class = self._find_tool_class(module, tool_name)
            
            # Store module info
            mod_info = ModuleInfo(
                name=module_path,
                module=tool_class or module,
            )
            self.modules[module_path] = mod_info
            
            return mod_info.module
            
        except ImportError as e:
            _LOG.error(f"Failed to load module {module_path}: {e}")
            raise
        except Exception as e:
            _LOG.error(f"Error loading module {module_path}: {e}")
            raise
    
    def unload_module(self, module_path: str) -> bool:
        """
        Unload a module and free memory.
        
        Args:
            module_path: Full module path
        
        Returns:
            True if unloaded, False if not found
        """
        if module_path not in self.modules:
            return False
        
        _LOG.info(f"Unloading module: {module_path}")
        
        # Remove from our tracking
        mod_info = self.modules.pop(module_path)
        
        # Remove from sys.modules
        if module_path in sys.modules:
            del sys.modules[module_path]
        
        # Remove references
        del mod_info
        
        # Force garbage collection
        gc.collect()
        
        _LOG.debug(f"Module {module_path} unloaded")
        return True
    
    def unload_idle_modules(self) -> int:
        """
        Unload modules that have been idle for too long.
        
        Returns:
            Number of modules unloaded
        """
        to_unload = [
            path for path, info in self.modules.items()
            if info.idle_time > self.idle_timeout
        ]
        
        for path in to_unload:
            self.unload_module(path)
        
        if to_unload:
            _LOG.info(f"Unloaded {len(to_unload)} idle modules")
        
        return len(to_unload)
    
    def unload_all(self) -> int:
        """
        Unload all modules.
        
        Returns:
            Number of modules unloaded
        """
        count = len(self.modules)
        module_paths = list(self.modules.keys())
        
        for path in module_paths:
            self.unload_module(path)
        
        # Extra garbage collection
        gc.collect()
        
        _LOG.info(f"Unloaded all {count} modules")
        return count
    
    def get_loaded_modules(self) -> Dict[str, ModuleInfo]:
        """Get information about currently loaded modules."""
        return dict(self.modules)
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get module loader metrics.
        
        Returns:
            Dictionary with metrics
        """
        return {
            "total_loaded": len(self.modules),
            "modules_by_category": self._count_by_category(),
            "idle_modules": len([
                m for m in self.modules.values()
                if m.idle_time > self.idle_timeout
            ]),
            "most_accessed": sorted(
                [
                    {
                        "name": info.name,
                        "accesses": info.access_count,
                        "idle_time": info.idle_time,
                    }
                    for info in self.modules.values()
                ],
                key=lambda x: x["accesses"],
                reverse=True
            )[:5],
        }
    
    def _find_tool_class(self, module: Any, tool_name: str) -> Optional[Any]:
        """
        Try to find the tool class in a module.
        
        Args:
            module: The imported module
            tool_name: Tool name to search for
        
        Returns:
            Tool class if found, None otherwise
        """
        # Common naming patterns
        class_names = [
            tool_name.replace("_", " ").title().replace(" ", ""),
            tool_name.title(),
            f"{tool_name.title()}Tool",
            f"{tool_name.replace('_', '')}",
        ]
        
        for class_name in class_names:
            if hasattr(module, class_name):
                return getattr(module, class_name)
        
        # Try to find any class that looks like a tool
        for attr_name in dir(module):
            if attr_name.startswith("_"):
                continue
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and hasattr(attr, "run"):
                return attr
        
        return None
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count loaded modules by category."""
        counts: Dict[str, int] = {}
        for info in self.modules.values():
            # Extract category from module path
            parts = info.name.split(".")
            if len(parts) >= 3 and parts[0] == "ctf_helper" and parts[1] == "modules":
                category = parts[2]
                counts[category] = counts.get(category, 0) + 1
        return counts


# Global singleton instance
_module_loader: Optional[ModuleLoader] = None


def get_module_loader() -> ModuleLoader:
    """Get the global module loader instance."""
    global _module_loader
    if _module_loader is None:
        _module_loader = ModuleLoader()
    return _module_loader


# Convenience alias
module_loader = get_module_loader()
