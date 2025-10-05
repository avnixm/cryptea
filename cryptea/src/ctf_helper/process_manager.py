"""
Process Manager for Cryptea
Handles lifecycle of subprocesses spawned by tools to ensure proper cleanup.
"""

from __future__ import annotations

import asyncio
import gc
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from gi.repository import GLib  # type: ignore[import]

from .logger import configure_logging

_LOG = configure_logging()


@dataclass
class ProcessInfo:
    """Information about a running process."""

    name: str
    process: subprocess.Popen
    started_at: float = field(default_factory=time.time)
    tool_category: Optional[str] = None
    challenge_id: Optional[int] = None
    pid: int = field(init=False)
    
    def __post_init__(self) -> None:
        self.pid = self.process.pid
    
    @property
    def runtime(self) -> float:
        """Get process runtime in seconds."""
        return time.time() - self.started_at
    
    @property
    def is_alive(self) -> bool:
        """Check if process is still running."""
        return self.process.poll() is None


class ProcessManager:
    """
    Global process manager for tracking and cleaning up subprocesses.
    
    Features:
    - Tracks all subprocesses launched by Cryptea tools
    - Gracefully terminates processes when tools are closed
    - Kills runaway processes after timeout
    - Provides process metrics for monitoring
    - Prevents zombie processes
    """

    _instance: Optional[ProcessManager] = None
    _lock = threading.Lock()

    def __new__(cls) -> ProcessManager:
        """Singleton pattern to ensure only one process manager exists."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the process manager (only once)."""
        if self._initialized:
            return
        
        self.processes: Dict[str, ProcessInfo] = {}
        self._termination_timeout = 3.0  # Seconds to wait before SIGKILL
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_interval = 300.0  # 5 minutes
        self._running = False
        self._initialized = True
        
        _LOG.info("ProcessManager initialized")
    
    def start(
        self,
        name: str,
        cmd: List[str] | str,
        *,
        shell: bool = False,
        cwd: Optional[str | Path] = None,
        env: Optional[Dict[str, str]] = None,
        tool_category: Optional[str] = None,
        challenge_id: Optional[int] = None,
        stdout: int = subprocess.PIPE,
        stderr: int = subprocess.PIPE,
    ) -> subprocess.Popen:
        """
        Start a subprocess and track it.
        
        Args:
            name: Unique identifier for this process
            cmd: Command to execute (list of args or shell string)
            shell: Whether to use shell execution
            cwd: Working directory
            env: Environment variables
            tool_category: Category of the tool (e.g., 'forensics', 'crypto')
            challenge_id: Associated challenge ID
            stdout: Standard output handling
            stderr: Standard error handling
        
        Returns:
            The subprocess.Popen object
        """
        # Stop any existing process with the same name
        if name in self.processes:
            _LOG.warning(f"Process '{name}' already exists, stopping it first")
            self.stop(name)
        
        # Prepare command
        if isinstance(cmd, str) and not shell:
            cmd = cmd.split()
        
        # Start in new process group for clean termination
        try:
            process = subprocess.Popen(
                cmd,
                shell=shell,
                cwd=cwd,
                env=env,
                stdout=stdout,
                stderr=stderr,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
                start_new_session=True if not hasattr(os, 'setsid') else False,
            )
            
            # Track the process
            proc_info = ProcessInfo(
                name=name,
                process=process,
                tool_category=tool_category,
                challenge_id=challenge_id,
            )
            self.processes[name] = proc_info
            
            _LOG.info(
                f"Started process '{name}' (PID {process.pid})"
                + (f" for challenge {challenge_id}" if challenge_id else "")
            )
            
            return process
            
        except Exception as e:
            _LOG.error(f"Failed to start process '{name}': {e}")
            raise
    
    def stop(self, name: str, *, force: bool = False) -> bool:
        """
        Stop a tracked process.
        
        Args:
            name: Process identifier
            force: If True, skip graceful termination and kill immediately
        
        Returns:
            True if process was stopped, False if not found
        """
        proc_info = self.processes.get(name)
        if proc_info is None:
            _LOG.debug(f"Process '{name}' not found or already stopped")
            return False
        
        process = proc_info.process
        
        # Check if already terminated
        if not proc_info.is_alive:
            self.processes.pop(name, None)
            _LOG.debug(f"Process '{name}' already terminated")
            return True
        
        _LOG.info(f"Stopping process '{name}' (PID {process.pid})")
        
        try:
            if force:
                # Immediate kill
                self._kill_process_group(process)
            else:
                # Graceful termination
                self._terminate_process_group(process)
                
                # Wait for termination with timeout
                try:
                    process.wait(timeout=self._termination_timeout)
                except subprocess.TimeoutExpired:
                    _LOG.warning(
                        f"Process '{name}' did not terminate gracefully, forcing kill"
                    )
                    self._kill_process_group(process)
                    process.wait(timeout=1.0)
            
            self.processes.pop(name, None)
            _LOG.info(f"Process '{name}' stopped successfully")
            return True
            
        except Exception as e:
            _LOG.error(f"Error stopping process '{name}': {e}")
            # Still remove from tracking
            self.processes.pop(name, None)
            return False
    
    def stop_all(self, *, force: bool = False) -> None:
        """
        Stop all tracked processes.
        
        Args:
            force: If True, kill all processes immediately
        """
        if not self.processes:
            _LOG.debug("No processes to stop")
            return
        
        _LOG.info(f"Stopping all processes ({len(self.processes)} active)")
        
        # Make a copy of keys to avoid modification during iteration
        process_names = list(self.processes.keys())
        
        for name in process_names:
            try:
                self.stop(name, force=force)
            except Exception as e:
                _LOG.error(f"Error stopping process '{name}': {e}")
        
        _LOG.info("All processes stopped")
    
    def stop_by_category(self, category: str) -> int:
        """
        Stop all processes in a specific category.
        
        Args:
            category: Tool category to stop
        
        Returns:
            Number of processes stopped
        """
        to_stop = [
            name for name, info in self.processes.items()
            if info.tool_category == category
        ]
        
        for name in to_stop:
            self.stop(name)
        
        return len(to_stop)
    
    def stop_by_challenge(self, challenge_id: int) -> int:
        """
        Stop all processes associated with a challenge.
        
        Args:
            challenge_id: Challenge ID
        
        Returns:
            Number of processes stopped
        """
        to_stop = [
            name for name, info in self.processes.items()
            if info.challenge_id == challenge_id
        ]
        
        for name in to_stop:
            self.stop(name)
        
        return len(to_stop)
    
    def get_process(self, name: str) -> Optional[subprocess.Popen]:
        """Get a process by name."""
        proc_info = self.processes.get(name)
        return proc_info.process if proc_info else None
    
    def get_process_info(self, name: str) -> Optional[ProcessInfo]:
        """Get process info by name."""
        return self.processes.get(name)
    
    def is_running(self, name: str) -> bool:
        """Check if a process is running."""
        proc_info = self.processes.get(name)
        if proc_info is None:
            return False
        return proc_info.is_alive
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get process metrics for monitoring.
        
        Returns:
            Dictionary with metrics
        """
        # Clean up dead processes
        self._cleanup_dead_processes()
        
        alive_processes = [
            info for info in self.processes.values()
            if info.is_alive
        ]
        
        return {
            "total_processes": len(alive_processes),
            "processes_by_category": self._count_by_category(),
            "processes_by_challenge": self._count_by_challenge(),
            "long_running": [
                {
                    "name": info.name,
                    "runtime": info.runtime,
                    "pid": info.pid,
                    "category": info.tool_category,
                }
                for info in alive_processes
                if info.runtime > 60.0  # Over 1 minute
            ],
        }
    
    def start_cleanup_thread(self) -> None:
        """Start background thread for periodic cleanup."""
        if self._cleanup_thread is not None and self._cleanup_thread.is_alive():
            return
        
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="ProcessManager-Cleanup"
        )
        self._cleanup_thread.start()
        _LOG.info("Cleanup thread started")
    
    def stop_cleanup_thread(self) -> None:
        """Stop the background cleanup thread."""
        self._running = False
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=2.0)
            _LOG.info("Cleanup thread stopped")
    
    def _cleanup_loop(self) -> None:
        """Background loop for cleaning up dead processes."""
        while self._running:
            try:
                time.sleep(self._cleanup_interval)
                if self._running:
                    self._cleanup_dead_processes()
            except Exception as e:
                _LOG.error(f"Error in cleanup loop: {e}")
    
    def _cleanup_dead_processes(self) -> int:
        """Remove dead processes from tracking."""
        dead = [
            name for name, info in self.processes.items()
            if not info.is_alive
        ]
        
        for name in dead:
            proc_info = self.processes.pop(name)
            _LOG.debug(f"Cleaned up dead process '{name}' (PID {proc_info.pid})")
        
        if dead:
            # Trigger garbage collection after cleanup
            gc.collect()
        
        return len(dead)
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count processes by category."""
        counts: Dict[str, int] = {}
        for info in self.processes.values():
            if info.is_alive and info.tool_category:
                counts[info.tool_category] = counts.get(info.tool_category, 0) + 1
        return counts
    
    def _count_by_challenge(self) -> Dict[int, int]:
        """Count processes by challenge."""
        counts: Dict[int, int] = {}
        for info in self.processes.values():
            if info.is_alive and info.challenge_id:
                counts[info.challenge_id] = counts.get(info.challenge_id, 0) + 1
        return counts
    
    def _terminate_process_group(self, process: subprocess.Popen) -> None:
        """Send SIGTERM to process group."""
        try:
            if hasattr(os, 'killpg'):
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
        except Exception as e:
            _LOG.warning(f"Error terminating process group: {e}")
    
    def _kill_process_group(self, process: subprocess.Popen) -> None:
        """Send SIGKILL to process group."""
        try:
            if hasattr(os, 'killpg'):
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        except Exception as e:
            _LOG.warning(f"Error killing process group: {e}")
    
    def __del__(self) -> None:
        """Cleanup on destruction."""
        try:
            self.stop_cleanup_thread()
            self.stop_all(force=True)
        except Exception:
            pass


# Global singleton instance
_process_manager: Optional[ProcessManager] = None


def get_process_manager() -> ProcessManager:
    """Get the global process manager instance."""
    global _process_manager
    if _process_manager is None:
        _process_manager = ProcessManager()
    return _process_manager


# Convenience alias
process_manager = get_process_manager()
