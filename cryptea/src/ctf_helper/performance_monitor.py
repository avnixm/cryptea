"""
Performance Monitor for Cryptea
Tracks CPU, memory, and process metrics for developer mode.
"""

from __future__ import annotations

import os
import psutil  # type: ignore[import]
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .logger import configure_logging
from .process_manager import get_process_manager
from .module_loader import get_module_loader

_LOG = configure_logging()


@dataclass
class PerformanceSnapshot:
    """Single performance measurement."""

    timestamp: float
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    active_processes: int
    loaded_modules: int
    thread_count: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "memory_percent": self.memory_percent,
            "active_processes": self.active_processes,
            "loaded_modules": self.loaded_modules,
            "thread_count": self.thread_count,
        }


class PerformanceMonitor:
    """
    Performance monitoring and metrics collection.
    
    Features:
    - Real-time CPU and memory tracking
    - Process count monitoring
    - Module load tracking
    - Historical metrics with rolling window
    - Developer mode logging
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        history_size: int = 100,
        sample_interval: float = 5.0
    ) -> None:
        """
        Initialize the performance monitor.
        
        Args:
            enabled: Whether monitoring is active
            history_size: Number of historical snapshots to keep
            sample_interval: Seconds between samples
        """
        self.enabled = enabled
        self.history_size = history_size
        self.sample_interval = sample_interval
        
        self.history: List[PerformanceSnapshot] = []
        self._process = psutil.Process(os.getpid())
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._baseline: Optional[PerformanceSnapshot] = None
        
        _LOG.info(
            f"PerformanceMonitor initialized "
            f"(enabled={enabled}, interval={sample_interval}s)"
        )
    
    def start(self) -> None:
        """Start performance monitoring."""
        if not self.enabled:
            _LOG.debug("Performance monitoring is disabled")
            return
        
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            _LOG.warning("Performance monitor already running")
            return
        
        # Take baseline measurement
        self._baseline = self._take_snapshot()
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="PerformanceMonitor"
        )
        self._monitor_thread.start()
        _LOG.info("Performance monitoring started")
    
    def stop(self) -> None:
        """Stop performance monitoring."""
        if not self._running:
            return
        
        self._running = False
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=2.0)
        _LOG.info("Performance monitoring stopped")
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """
        Get current performance metrics.
        
        Returns:
            Dictionary with current metrics
        """
        snapshot = self._take_snapshot()
        
        metrics = snapshot.to_dict()
        
        # Add deltas from baseline
        if self._baseline:
            metrics["delta_cpu"] = snapshot.cpu_percent - self._baseline.cpu_percent
            metrics["delta_memory_mb"] = snapshot.memory_mb - self._baseline.memory_mb
            metrics["delta_processes"] = snapshot.active_processes - self._baseline.active_processes
            metrics["delta_modules"] = snapshot.loaded_modules - self._baseline.loaded_modules
        
        # Add process manager metrics
        process_mgr = get_process_manager()
        metrics["process_details"] = process_mgr.get_metrics()
        
        # Add module loader metrics
        mod_loader = get_module_loader()
        metrics["module_details"] = mod_loader.get_metrics()
        
        return metrics
    
    def get_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get historical metrics.
        
        Args:
            limit: Maximum number of historical snapshots to return
        
        Returns:
            List of metric dictionaries
        """
        history = self.history[-limit:] if limit else self.history
        return [snap.to_dict() for snap in history]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistical summary of performance.
        
        Returns:
            Dictionary with statistics
        """
        if not self.history:
            return {}
        
        cpu_values = [s.cpu_percent for s in self.history]
        mem_values = [s.memory_mb for s in self.history]
        proc_values = [s.active_processes for s in self.history]
        mod_values = [s.loaded_modules for s in self.history]
        
        return {
            "cpu": {
                "min": min(cpu_values),
                "max": max(cpu_values),
                "avg": sum(cpu_values) / len(cpu_values),
                "current": cpu_values[-1],
            },
            "memory_mb": {
                "min": min(mem_values),
                "max": max(mem_values),
                "avg": sum(mem_values) / len(mem_values),
                "current": mem_values[-1],
            },
            "active_processes": {
                "min": min(proc_values),
                "max": max(proc_values),
                "avg": sum(proc_values) / len(proc_values),
                "current": proc_values[-1],
            },
            "loaded_modules": {
                "min": min(mod_values),
                "max": max(mod_values),
                "avg": sum(mod_values) / len(mod_values),
                "current": mod_values[-1],
            },
            "samples": len(self.history),
            "duration_seconds": (
                self.history[-1].timestamp - self.history[0].timestamp
                if len(self.history) > 1 else 0
            ),
        }
    
    def reset_baseline(self) -> None:
        """Reset the performance baseline."""
        self._baseline = self._take_snapshot()
        _LOG.info("Performance baseline reset")
    
    def clear_history(self) -> None:
        """Clear historical metrics."""
        self.history.clear()
        _LOG.info("Performance history cleared")
    
    def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                snapshot = self._take_snapshot()
                self.history.append(snapshot)
                
                # Trim history to size limit
                if len(self.history) > self.history_size:
                    self.history = self.history[-self.history_size:]
                
                # Log warnings for high resource usage
                if snapshot.memory_percent > 80.0:
                    _LOG.warning(
                        f"High memory usage: {snapshot.memory_mb:.1f} MB "
                        f"({snapshot.memory_percent:.1f}%)"
                    )
                
                if snapshot.cpu_percent > 80.0:
                    _LOG.warning(f"High CPU usage: {snapshot.cpu_percent:.1f}%")
                
                # Sleep until next sample
                time.sleep(self.sample_interval)
                
            except Exception as e:
                _LOG.error(f"Error in monitoring loop: {e}")
                time.sleep(self.sample_interval)
    
    def _take_snapshot(self) -> PerformanceSnapshot:
        """Take a performance snapshot."""
        # Get process manager metrics
        process_mgr = get_process_manager()
        process_metrics = process_mgr.get_metrics()
        
        # Get module loader metrics
        mod_loader = get_module_loader()
        mod_metrics = mod_loader.get_metrics()
        
        # Get system metrics
        cpu_percent = self._process.cpu_percent(interval=0.1)
        mem_info = self._process.memory_info()
        memory_mb = mem_info.rss / 1024 / 1024  # Convert bytes to MB
        memory_percent = self._process.memory_percent()
        thread_count = self._process.num_threads()
        
        return PerformanceSnapshot(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_mb=memory_mb,
            memory_percent=memory_percent,
            active_processes=process_metrics["total_processes"],
            loaded_modules=mod_metrics["total_loaded"],
            thread_count=thread_count,
        )


# Global singleton instance
_performance_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor(*, enabled: bool = False) -> PerformanceMonitor:
    """Get the global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor(enabled=enabled)
    return _performance_monitor


# Convenience alias
performance_monitor = get_performance_monitor()
