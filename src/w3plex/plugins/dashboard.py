"""Hierarchical dashboard system based on Rich Live.

Provides a hierarchical page structure with pagination support for terminal dashboards.
Only one Rich Live instance exists at a time, but content can be switched between pages.

Architecture:
- DashboardPlugin: Plugin to initialize dashboard in process_action_data
- DashboardManager: Singleton managing the global Live instance and page hierarchy
- DashboardLevel: A level in the hierarchy containing multiple sibling pages
- DashboardPage: Individual page with renderable content

Usage:
    # Apply DashboardPlugin in your action
    async with apply_plugins(DashboardPlugin()):
        ...

    async with dashboard_page("Main") as page:
        page.register_panel("Status", [("Key", "{value}")])
        page.set_variable_provider(lambda: {"value": "Hello"})

        async with dashboard_page("Child") as child:
            child.register_panel("Child Panel", [...])

Navigation hotkeys:
    ← / h      Previous page
    → / l      Next page
    ↑ / k      Navigate up (parent level)
    ↓ / j      Navigate down (child level)
    q          Quit dashboard
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
from collections import deque
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    AsyncIterator,
    Protocol,
    runtime_checkable,
)

from w3plex import Plugin
from rich import box
from rich.console import Console, Group, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from w3plex import Action


_current_level: ContextVar[Optional["DashboardLevel"]] = ContextVar(
    "_current_level", default=None
)

_dashboard_manager: Optional["DashboardManager"] = None


def _get_dashboard_manager() -> "DashboardManager":
    """Get or create the global dashboard manager."""
    global _dashboard_manager
    if _dashboard_manager is None:
        _dashboard_manager = DashboardManager()
    return _dashboard_manager


@dataclass
class PanelDefinition:
    """Definition for a dashboard panel with key-value rows."""
    name: str
    rows: List[Tuple[str, str]]


@dataclass
class KeyEvent:
    """Normalized key events we care about."""
    kind: str  # "char" | "left" | "right" | "up" | "down" | "ctrl_c"
    value: Optional[str] = None


@runtime_checkable
class IDashboard(Protocol):
    """Protocol defining the dashboard interface.

    Any class implementing these methods can be used as a dashboard.
    DashboardPage implements this protocol.
    """

    @property
    def title(self) -> str:
        """Page title displayed in navigation."""
        ...

    def register_panel(
        self,
        name: str,
        rows: List[Tuple[str, str]]
    ) -> None:
        """Register a panel with key-value rows."""
        ...

    def register_custom_panel(
        self,
        name: str,
        renderer: Callable[[Optional[Dict[str, Any]]], RenderableType]
    ) -> None:
        """Register a custom panel with a render callback."""
        ...

    def set_variable_provider(
        self,
        provider: Callable[[], Dict[str, Any]]
    ) -> None:
        """Set the variable provider for panel formatting."""
        ...

    def set_renderable(self, renderable: RenderableType) -> None:
        """Set a custom renderable to display instead of panels."""
        ...

    def set_layout(self, layout: Layout) -> None:
        """Set a custom layout for the page."""
        ...

    def set_panel_columns(
        self,
        right_titles: List[str],
        left_titles: Optional[List[str]] = None,
    ) -> None:
        """Split panels into left/right columns by title."""
        ...

    def reset(self) -> None:
        """Reset all panels, layouts, and providers for this page."""
        ...

    def render(self) -> RenderableType:
        """Render the page content."""
        ...


class DashboardPage:
    """Individual dashboard page with panels and content.

    Provides an interface for building dashboard layouts with panels,
    tables, and custom renderables.
    """

    def __init__(self, title: str, level: "DashboardLevel") -> None:
        self._title = title
        self._level = level
        self._panels: List[PanelDefinition] = []
        self._custom_panels: Dict[str, Callable[[Optional[Dict[str, Any]]], RenderableType]] = {}
        self._variable_provider: Optional[Callable[[], Dict[str, Any]]] = None
        self._layout: Optional[Layout] = None
        self._custom_renderable: Optional[RenderableType] = None
        self._panel_columns: Optional[Dict[str, Optional[set[str]]]] = None

    @property
    def title(self) -> str:
        return self._title

    @property
    def level(self) -> "DashboardLevel":
        return self._level

    def register_panel(
        self,
        name: str,
        rows: List[Tuple[str, str]]
    ) -> None:
        """Register a panel with key-value rows.

        Args:
            name: Panel title
            rows: List of (label, format_string) tuples.
                  Format strings can use {variable} placeholders.
        """
        self._panels.append(PanelDefinition(name=name, rows=rows))

    def register_custom_panel(
        self,
        name: str,
        renderer: Callable[[Optional[Dict[str, Any]]], RenderableType]
    ) -> None:
        """Register a custom panel with a render callback.

        Args:
            name: Panel title
            renderer: Callable that receives variables dict and returns renderable
        """
        self._custom_panels[name] = renderer

    def set_variable_provider(
        self,
        provider: Callable[[], Dict[str, Any]]
    ) -> None:
        """Set the variable provider for panel formatting.

        Args:
            provider: Callable returning dict of variables for format strings
        """
        self._variable_provider = provider

    def set_renderable(self, renderable: RenderableType) -> None:
        """Set a custom renderable to display instead of panels.

        Args:
            renderable: Any Rich renderable object
        """
        self._custom_renderable = renderable

    def set_layout(self, layout: Layout) -> None:
        """Set a custom layout for the page.

        Args:
            layout: Rich Layout object for complex layouts
        """
        self._layout = layout

    def set_panel_columns(
        self,
        right_titles: List[str],
        left_titles: Optional[List[str]] = None,
    ) -> None:
        """Split panels into left/right columns by title."""
        self._panel_columns = {
            "right": set(right_titles or []),
            "left": set(left_titles) if left_titles is not None else None,
        }

    def reset(self) -> None:
        """Reset all panels, layouts, and providers for this page."""
        self._panels.clear()
        self._custom_panels.clear()
        self._variable_provider = None
        self._layout = None
        self._custom_renderable = None
        self._panel_columns = None

    def _get_variables(self) -> Dict[str, Any]:
        """Get current variables from provider."""
        if self._variable_provider is None:
            return {}
        return self._variable_provider()

    def _render_panel(self, panel_def: PanelDefinition, variables: Dict[str, Any]) -> Panel:
        """Render a single panel with variable substitution."""
        table = Table.grid(padding=(0, 1))
        table.add_column(justify="right", style="bold cyan", no_wrap=True)
        table.add_column(justify="left")

        for label, fmt in panel_def.rows:
            try:
                value = fmt.format(**variables)
            except (KeyError, ValueError, IndexError):
                value = fmt
            table.add_row(label, value)

        return Panel(table, title=panel_def.name, border_style="blue")

    def render(self) -> RenderableType:
        """Render the page content."""
        if self._layout is not None:
            return self._layout

        if self._custom_renderable is not None:
            return self._custom_renderable

        variables = self._get_variables()
        renderables: List[Tuple[str, RenderableType]] = []

        for panel_def in self._panels:
            renderables.append((panel_def.name, self._render_panel(panel_def, variables)))

        for name, renderer in self._custom_panels.items():
            content = renderer(variables)
            renderables.append((name, Panel(content, title=name, border_style="blue")))

        if not renderables:
            return Text("Empty page", style="dim")

        if self._panel_columns and self._panel_columns.get("right"):
            right_titles = self._panel_columns["right"] or set()
            left_titles = self._panel_columns.get("left")
            left_renderables: List[RenderableType] = []
            right_renderables: List[RenderableType] = []
            for title, renderable in renderables:
                if left_titles is not None:
                    if title in left_titles:
                        left_renderables.append(renderable)
                    elif title in right_titles:
                        right_renderables.append(renderable)
                    else:
                        left_renderables.append(renderable)
                else:
                    if title in right_titles:
                        right_renderables.append(renderable)
                    else:
                        left_renderables.append(renderable)

            if right_renderables:
                layout = Layout()
                layout.split_row(
                    Layout(name="left", ratio=1),
                    Layout(name="right", ratio=1),
                )
                layout["left"].update(Group(*left_renderables) if left_renderables else Text(""))
                layout["right"].update(Group(*right_renderables))
                return layout

        return Group(*[renderable for _, renderable in renderables])


class DashboardLevel:
    """A level in the dashboard hierarchy containing sibling pages.

    Supports pagination to switch between pages at this level.
    Child levels can be created from any page.
    """

    def __init__(
        self,
        parent: Optional["DashboardLevel"] = None,
        parent_page: Optional[DashboardPage] = None
    ) -> None:
        self._parent = parent
        self._parent_page = parent_page
        self._pages: List[DashboardPage] = []
        self._active_index: int = 0
        self._child_level: Optional["DashboardLevel"] = None

    @property
    def parent(self) -> Optional["DashboardLevel"]:
        return self._parent

    @property
    def parent_page(self) -> Optional[DashboardPage]:
        return self._parent_page

    @property
    def pages(self) -> List[DashboardPage]:
        return self._pages

    @property
    def active_page(self) -> Optional[DashboardPage]:
        if 0 <= self._active_index < len(self._pages):
            return self._pages[self._active_index]
        return None

    @property
    def active_index(self) -> int:
        return self._active_index

    @property
    def child_level(self) -> Optional["DashboardLevel"]:
        return self._child_level

    @property
    def has_child(self) -> bool:
        return self._child_level is not None and len(self._child_level.pages) > 0

    def add_page(self, page: DashboardPage) -> None:
        """Add a page to this level."""
        self._pages.append(page)
        if len(self._pages) == 1:
            self._active_index = 0

    def remove_page(self, page: DashboardPage) -> None:
        """Remove a page from this level."""
        if page in self._pages:
            idx = self._pages.index(page)
            self._pages.remove(page)
            if self._active_index >= len(self._pages) and self._pages:
                self._active_index = len(self._pages) - 1
            elif not self._pages:
                self._active_index = 0

    def next_page(self) -> Optional[DashboardPage]:
        """Switch to the next page. Returns the new active page."""
        if not self._pages:
            return None
        self._active_index = (self._active_index + 1) % len(self._pages)
        return self.active_page

    def prev_page(self) -> Optional[DashboardPage]:
        """Switch to the previous page. Returns the new active page."""
        if not self._pages:
            return None
        self._active_index = (self._active_index - 1) % len(self._pages)
        return self.active_page

    def goto_page(self, index: int) -> Optional[DashboardPage]:
        """Switch to a specific page by index. Returns the new active page."""
        if not self._pages:
            return None
        self._active_index = max(0, min(index, len(self._pages) - 1))
        return self.active_page

    def create_child_level(self, parent_page: DashboardPage) -> "DashboardLevel":
        """Create a child level under the given page."""
        self._child_level = DashboardLevel(parent=self, parent_page=parent_page)
        return self._child_level

    def clear_child_level(self) -> None:
        """Remove the child level."""
        self._child_level = None

    def get_depth(self) -> int:
        """Get the depth of this level in the hierarchy (0 = root)."""
        depth = 0
        level = self._parent
        while level:
            depth += 1
            level = level._parent
        return depth


class KeyboardHandler:
    """
    Async keyboard listener designed to NOT break rich.Live.

    Key points vs your original:
      - Uses tty.setcbreak (NOT setraw) so terminal output processing remains intact
        and Ctrl+C stays a signal (KeyboardInterrupt) instead of turning into '\\x03'.
      - Reads from the TTY FD via os.read + select (non-blocking), never sys.stdin.read(2).
      - Avoids blocking on partial escape sequences (arrow keys).
      - Restores termios settings on exit.
    """

    def __init__(self, manager: "DashboardManager") -> None:
        self._manager = manager
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None

        self._fd: Optional[int] = None
        self._old_termios: Optional[list[int]] = None

        # Buffer for escape sequences (arrows)
        self._esc_buf: str = ""
        self._esc_deadline: float = 0.0

    async def start(self) -> None:
        if self._running:
            return
        # Use the real stdin if available; but we only need the FD to be a TTY
        if not sys.__stdin__.isatty():
            return

        self._running = True
        self._task = asyncio.create_task(self._listen_loop(), name="keyboard_handler")

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _listen_loop(self) -> None:
        import select
        import termios
        import tty
        import time

        fd = sys.__stdin__.fileno()
        self._fd = fd
        self._old_termios = termios.tcgetattr(fd)

        try:
            # Critical: cbreak keeps output processing sane for rich.Live
            # and Ctrl+C remains a signal.
            tty.setcbreak(fd)

            while self._running:
                # If we have a pending ESC buffer, we allow a very short time
                # to collect the rest of the sequence without blocking.
                now = time.monotonic()
                timeout = 0.0
                if self._esc_buf:
                    timeout = max(0.0, self._esc_deadline - now)

                r, _, _ = select.select([fd], [], [], timeout)
                if not r:
                    # If ESC sequence timed out, treat ESC as a standalone key and clear.
                    if self._esc_buf and time.monotonic() >= self._esc_deadline:
                        await self._dispatch(KeyEvent(kind="char", value="\x1b"))
                        self._esc_buf = ""
                    await asyncio.sleep(0.01)
                    continue

                raw = os.read(fd, 64)
                if not raw:
                    await asyncio.sleep(0.01)
                    continue

                text = raw.decode(errors="ignore")
                for ch in text:
                    await self._consume_char(ch)

        except asyncio.CancelledError:
            raise
        except KeyboardInterrupt:
            # With cbreak, Ctrl+C will likely come here as KeyboardInterrupt
            await self._dispatch(KeyEvent(kind="ctrl_c"))
        finally:
            # Always restore terminal
            try:
                if self._old_termios is not None:
                    termios.tcsetattr(fd, termios.TCSADRAIN, self._old_termios)
            except Exception:
                # Last-resort: don't crash on shutdown
                pass

    async def _consume_char(self, ch: str) -> None:
        import time

        # If we are building an escape sequence, extend the buffer and attempt parse
        if self._esc_buf:
            self._esc_buf += ch
            ev = self._try_parse_escape(self._esc_buf)
            if ev:
                self._esc_buf = ""
                await self._dispatch(ev)
            return

        # Start of escape sequence (arrows typically)
        if ch == "\x1b":
            self._esc_buf = "\x1b"
            self._esc_deadline = time.monotonic() + 0.03  # 30ms to gather rest
            return

        # Normal char
        await self._dispatch(KeyEvent(kind="char", value=ch))

    def _try_parse_escape(self, buf: str) -> Optional[KeyEvent]:
        """
        Typical arrow keys:
          ESC [ A  (up)
          ESC [ B  (down)
          ESC [ C  (right)
          ESC [ D  (left)
        Some terminals send ESC O A/B/C/D; support both.
        """
        if buf in ("\x1b[A", "\x1bOA"):
            return KeyEvent(kind="up")
        if buf in ("\x1b[B", "\x1bOB"):
            return KeyEvent(kind="down")
        if buf in ("\x1b[C", "\x1bOC"):
            return KeyEvent(kind="right")
        if buf in ("\x1b[D", "\x1bOD"):
            return KeyEvent(kind="left")

        # Not enough data yet? Keep buffering for known prefixes.
        if buf in ("\x1b", "\x1b[", "\x1bO"):
            return None

        # Unknown escape sequence: drop it silently (or handle as raw chars if you prefer)
        # Returning None keeps waiting until timeout; but for unknown sequences we should clear.
        # We'll treat it as "handled" by returning a char event for ESC and letting remaining
        # chars be processed normally would be more complex. We'll just stop buffering.
        return KeyEvent(kind="char", value=buf)

    async def _dispatch(self, ev: KeyEvent) -> None:
        """
        Wire events to your manager actions.

        Adjust this mapping to match your DashboardManager API.
        """
        if ev.kind == "left":
            self._manager.navigate_prev()
            return
        if ev.kind == "right":
            self._manager.navigate_next()
            return
        if ev.kind == "up":
            self._manager.navigate_up()
            return
        if ev.kind == "down":
            self._manager.navigate_down()
            return

        if ev.kind == "ctrl_c":
            await self._manager.request_quit()
            return

        if ev.kind == "char":
            ch = ev.value or ""
            # Quit
            if ch in ("q", "Q"):
                await self._manager.request_quit()
                return

            # Optional: WASD navigation (nice for raw terminals)
            if ch in ("h", "H"):
                self._manager.navigate_prev()
                return
            if ch in ("l", "L"):
                self._manager.navigate_next()
                return
            if ch in ("k", "K"):
                self._manager.navigate_up()
                return
            if ch in ("j", "J"):
                self._manager.navigate_down()
                return

            # Optional: pass through to manager for custom bindings
            if hasattr(self._manager, "handle_key"):
                try:
                    maybe = self._manager.handle_key(ch)
                    if asyncio.iscoroutine(maybe):
                        await maybe
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # Don't let key handling crash the dashboard
                    pass


class DashboardManager:
    """Singleton manager for the dashboard system.

    Manages the Rich Live instance and the hierarchy of dashboard levels.
    Only one Live can be active in the terminal at a time.
    """

    def __init__(self) -> None:
        self._console = Console()
        self._live: Optional[Live] = None
        self._root_level: Optional[DashboardLevel] = None
        self._active_level: Optional[DashboardLevel] = None
        self._refresh_rate: float = 4.0
        self._running: bool = False
        self._update_task: Optional[asyncio.Task] = None
        self._keyboard: Optional[KeyboardHandler] = None
        self._quit_requested: bool = False
        self._quit_event: Optional[asyncio.Event] = None
        self._keyboard_enabled: bool = True

        self._lock = asyncio.Lock()

        # --- Loguru capture (active only while dashboard is running) ---
        self._loguru_capture_enabled: bool = True
        self._loguru_sink_id: Optional[int] = None
        self._loguru_saved_console_handlers: List[Dict[str, Any]] = []
        self._log_lines = deque(maxlen=200)
        self._log_lock = threading.Lock()

    @property
    def console(self) -> Console:
        return self._console

    @property
    def root_level(self) -> Optional[DashboardLevel]:
        return self._root_level

    @property
    def active_level(self) -> Optional[DashboardLevel]:
        return self._active_level

    @property
    def active_page(self) -> Optional[DashboardPage]:
        """Get the currently active page (deepest in hierarchy)."""
        level = self._get_deepest_level()
        if level:
            return level.active_page
        return None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def quit_requested(self) -> bool:
        return self._quit_requested

    def _get_deepest_level(self) -> Optional[DashboardLevel]:
        """Get the deepest level with pages in the hierarchy."""
        level = self._active_level
        while level and level.has_child:
            level = level.child_level
        return level

    def set_refresh_rate(self, rate: float) -> None:
        """Set the refresh rate in Hz."""
        self._refresh_rate = rate

    def set_keyboard_enabled(self, enabled: bool) -> None:
        """Enable or disable keyboard navigation."""
        self._keyboard_enabled = enabled

    def _ensure_root_level(self) -> DashboardLevel:
        """Ensure root level exists."""
        if self._root_level is None:
            self._root_level = DashboardLevel()
            self._active_level = self._root_level
        return self._root_level

    def get_or_create_level(self, parent_page: Optional[DashboardPage] = None) -> DashboardLevel:
        """Get existing level or create new one for the given context.

        If parent_page is None, returns/creates the root level.
        Otherwise, creates a child level under the parent page's level.
        """
        if parent_page is None:
            return self._ensure_root_level()

        parent_level = parent_page.level
        if parent_level.child_level is None:
            parent_level.create_child_level(parent_page)
        return parent_level.child_level  # type: ignore

    def _render_navigation_bar(self) -> RenderableType:
        """Render the navigation hints bar at the bottom."""
        level = self._get_deepest_level()

        hints = []

        if level and len(level.pages) > 1:
            hints.append("[bold]←/h[/] Prev")
            hints.append("[bold]→/l[/] Next")

        if level and level.parent:
            hints.append("[bold]↑/k[/] Up")

        if level and level.has_child:
            hints.append("[bold]↓/j[/] Down")

        hints.append("[bold]q[/] Quit")

        return Text.from_markup("  ".join(hints), style="dim")

    def _render_breadcrumb(self) -> RenderableType:
        """Render the breadcrumb navigation showing current position."""
        level = self._get_deepest_level()

        breadcrumb_parts: List[str] = []
        nav_level: Optional[DashboardLevel] = level

        while nav_level:
            page_title = nav_level.active_page.title if nav_level.active_page else "?"
            page_count = len(nav_level.pages)
            page_idx = nav_level.active_index + 1
            breadcrumb_parts.insert(0, f"{page_title} [{page_idx}/{page_count}]")
            nav_level = nav_level.parent

        breadcrumb = " > ".join(breadcrumb_parts)
        return Text(f"📊 {breadcrumb}", style="bold white on blue")

    def set_loguru_capture_enabled(self, enabled: bool) -> None:
        """Enable or disable Loguru capture into the dashboard UI.

        When enabled, Loguru console sinks (stdout/stderr) are temporarily removed
        while the dashboard is running, and logs are captured into an in-dashboard
        ring buffer rendered as a panel.
        """
        self._loguru_capture_enabled = enabled

    def _loguru_is_console_stream_handler(self, handler: Any) -> bool:
        """Best-effort detection of Loguru handlers that write to stdout/stderr.

        Loguru does not expose a public API to enumerate sinks. We use internal
        structures in a guarded way and only act on handlers that target
        sys.stdout/sys.stderr (or their __ counterparts).
        """
        try:
            sink = handler._sink  # type: ignore[attr-defined]
            stream = getattr(sink, "_stream", None)
            return stream in {sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__}
        except Exception:
            return False

    def _loguru_snapshot_handler(self, handler: Any) -> Dict[str, Any]:
        """Snapshot enough handler config to restore it later (best-effort)."""
        sink = getattr(handler, "_sink", None)
        stream = getattr(sink, "_stream", None)

        fmt = getattr(handler, "_decolorized_format", "{message}")
        ef = getattr(handler, "_exception_formatter", None)
        backtrace = bool(getattr(ef, "_backtrace", False))
        diagnose = bool(getattr(ef, "_diagnose", False))

        return {
            "stream": stream,
            "levelno": int(getattr(handler, "_levelno", 0)),
            "format": fmt,
            "colorize": bool(getattr(handler, "_colorize", False)),
            "serialize": bool(getattr(handler, "_serialize", False)),
            "enqueue": bool(getattr(handler, "_enqueue", False)),
            "filter": getattr(handler, "_filter", None),
            "backtrace": backtrace,
            "diagnose": diagnose,
        }

    def _install_loguru_capture(self) -> None:
        """Temporarily redirect Loguru console output into the dashboard UI.

        This is active only while the dashboard is running. It prevents logger
        output from fighting with rich.Live cursor control (which causes visible
        blinking/flicker).
        """
        if not self._loguru_capture_enabled:
            return

        try:
            from loguru import logger  # type: ignore
        except Exception:
            return

        self._loguru_saved_console_handlers.clear()

        # Remove only console stream sinks (stdout/stderr), keep file/network sinks intact
        try:
            handlers = getattr(getattr(logger, "_core"), "handlers")
            for hid, h in list(handlers.items()):
                if self._loguru_is_console_stream_handler(h):
                    self._loguru_saved_console_handlers.append(self._loguru_snapshot_handler(h))
                    logger.remove(hid)
        except Exception:
            # If internals differ, do nothing (fail safe)
            self._loguru_saved_console_handlers.clear()
            return

        def _sink(message: Any) -> None:
            line = str(message).rstrip("\n")
            if not line:
                return
            with self._log_lock:
                self._log_lines.append(line)

        # Single sink into ring buffer. enqueue=True makes it safe for threads.
        try:
            self._loguru_sink_id = logger.add(
                _sink,
                level=0,
                format="{time:HH:mm:ss.SSS} | {level:<8} | {name}:{function}:{line} - {message}",
                colorize=False,
                enqueue=True,
                backtrace=False,
                diagnose=False,
            )
        except Exception:
            self._loguru_sink_id = None

    def _remove_loguru_capture(self) -> None:
        """Remove dashboard Loguru sink and restore previous console sinks."""
        try:
            from loguru import logger  # type: ignore
        except Exception:
            return

        if self._loguru_sink_id is not None:
            try:
                logger.remove(self._loguru_sink_id)
            except Exception:
                pass
            self._loguru_sink_id = None

        for cfg in self._loguru_saved_console_handlers:
            stream = cfg.get("stream")
            if stream is None:
                continue
            try:
                logger.add(
                    stream,
                    level=cfg.get("levelno", 0),
                    format=cfg.get("format", "{message}"),
                    colorize=cfg.get("colorize", False),
                    serialize=cfg.get("serialize", False),
                    enqueue=cfg.get("enqueue", False),
                    filter=cfg.get("filter", None),
                    backtrace=cfg.get("backtrace", False),
                    diagnose=cfg.get("diagnose", False),
                )
            except Exception:
                pass

        self._loguru_saved_console_handlers.clear()

    def _render_logs_panel(self) -> Optional[RenderableType]:
        """Render captured Loguru logs as a panel (if any)."""
        with self._log_lock:
            lines = list(self._log_lines)
        if not lines:
            return None

        # Keep the panel readable; Rich will wrap long lines automatically.
        return Panel(
            Text("\n".join(lines)),
            title="Logs",
            box=box.SIMPLE,
            style="dim",
        )

    def _render(self) -> RenderableType:
        """Render the current dashboard view."""
        page = self.active_page
        if page is None:
            return Text("No active dashboard page", style="dim italic")

        header = self._render_breadcrumb()
        content = page.render()
        logs = self._render_logs_panel()
        footer = self._render_navigation_bar()

        parts: List[RenderableType] = [header, Text(""), content]
        if logs is not None:
            parts.extend([Text(""), logs])
        parts.extend([Text(""), Panel(footer, box=box.SIMPLE, style="dim")])

        return Group(*parts)

    async def start(self) -> None:
        """Start the dashboard Live display."""
        async with self._lock:
            if self._running:
                return

            if self._console._live is not None:
                try:
                    self._console._live.stop()
                except Exception:
                    pass
                self._console._live = None

            self._running = True
            self._quit_requested = False
            self._quit_event = asyncio.Event()

            self._live = Live(
                self._render(),
                console=self._console,
                refresh_per_second=self._refresh_rate,
                screen=False,
                auto_refresh=False,
                redirect_stdout=True,
                redirect_stderr=True,
            )
            self._live.start()
            self._install_loguru_capture()

            self._update_task = asyncio.create_task(self._update_loop())

            if self._keyboard_enabled and sys.stdin.isatty():
                self._keyboard = KeyboardHandler(self)
                await self._keyboard.start()

    async def stop(self) -> None:
        """Stop the dashboard Live display."""
        async with self._lock:
            if not self._running:
                return
            self._running = False

            try:
                self._remove_loguru_capture()

                if self._keyboard:
                    await self._keyboard.stop()
                    self._keyboard = None

                if self._update_task:
                    self._update_task.cancel()
                    try:
                        await self._update_task
                    except asyncio.CancelledError:
                        pass
                    self._update_task = None
            finally:
                if self._live:
                    try:
                        self._live.stop()
                    except Exception:
                        pass
                    self._live = None

    async def _update_loop(self) -> None:
        """Background loop to update the Live display."""
        while self._running and self._live:
            self._live.update(self._render(), refresh=True)
            await asyncio.sleep(1 / self._refresh_rate)

    def refresh(self) -> None:
        """Force a refresh of the display."""
        if self._live:
            self._live.update(self._render(), refresh=True)

    async def request_quit(self) -> None:
        """Request dashboard to quit."""
        self._quit_requested = True
        if self._quit_event:
            self._quit_event.set()

    async def wait_for_quit(self) -> None:
        """Wait until quit is requested."""
        if self._quit_event:
            await self._quit_event.wait()

    def navigate_up(self) -> bool:
        """Navigate to parent level. Returns True if successful."""
        level = self._get_deepest_level()

        if level and level.parent:
            level.parent.clear_child_level()
            self.refresh()
            return True
        return False

    def navigate_down(self) -> bool:
        """Navigate to child level. Returns True if successful."""
        level = self._get_deepest_level()

        if level and level.has_child and level.child_level:
            self.refresh()
            return True
        return False

    def navigate_next(self) -> bool:
        """Navigate to next page at current level. Returns True if successful."""
        level = self._get_deepest_level()

        if level and len(level.pages) > 1:
            level.next_page()
            self.refresh()
            return True
        return False

    def navigate_prev(self) -> bool:
        """Navigate to previous page at current level. Returns True if successful."""
        level = self._get_deepest_level()

        if level and len(level.pages) > 1:
            level.prev_page()
            self.refresh()
            return True
        return False


class DashboardPlugin(Plugin):
    """Plugin for initializing the dashboard system.

    Extends lazyplex Plugin to integrate with the application's plugin system.
    Initializes the dashboard manager during action data processing.
    """

    def __init__(
        self,
        refresh_rate: float = 4.0,
        keyboard_enabled: bool = True
    ) -> None:
        """Initialize dashboard plugin.

        Args:
            refresh_rate: Display refresh rate in Hz (default: 4.0)
            keyboard_enabled: Enable keyboard navigation (default: True)
        """
        self._refresh_rate = refresh_rate
        self._keyboard_enabled = keyboard_enabled
        self._manager: Optional[DashboardManager] = None

    @property
    def manager(self) -> DashboardManager:
        """Get the dashboard manager instance."""
        if self._manager is None:
            self._manager = _get_dashboard_manager()
        return self._manager

    async def process_action_data(
        self,
        process: Callable[["Action", Any], Awaitable],
        action: "Action",
        data: Any
    ):
        """Process action data and initialize dashboard.

        Called by the plugin system during action execution.
        Configures the dashboard manager before passing control to the next handler.
        """
        manager = self.manager
        manager.set_refresh_rate(self._refresh_rate)
        manager.set_keyboard_enabled(self._keyboard_enabled)

        return await process(action, data)

    @classmethod
    def get_manager(cls) -> DashboardManager:
        """Get the global dashboard manager instance."""
        return _get_dashboard_manager()


def get_dashboard() -> Optional[IDashboard]:
    """Get the current context's dashboard page.

    Returns the active dashboard page for the current execution context,
    or None if no dashboard page is active.

    Returns:
        The current DashboardPage implementing IDashboard, or None
    """
    level = _current_level.get()
    if level is None:
        return None
    return level.active_page


@asynccontextmanager
async def dashboard_page(
    title: str,
    auto_start: bool = True,
    auto_stop: bool = True
) -> AsyncIterator[IDashboard]:
    """Context manager for creating a dashboard page.

    Creates a new page on the current level. If no active level exists,
    creates the root level. If there's an active level from a parent context,
    creates a child level.

    Args:
        title: Page title displayed in navigation
        auto_start: Start Live display when entering first page
        auto_stop: Stop Live display when exiting last page

    Yields:
        DashboardPage instance for building the page layout

    Example:
        async with dashboard_page("Main Dashboard") as page:
            page.register_panel("Status", [
                ("Uptime", "{uptime}"),
                ("Connections", "{connections}"),
            ])
            page.set_variable_provider(get_stats)

            async with dashboard_page("Details") as child:
                child.register_panel("Details", [...])
    """
    manager = _get_dashboard_manager()
    current = _current_level.get()

    if current is None:
        level = manager.get_or_create_level(None)
    else:
        current_page = current.active_page
        level = manager.get_or_create_level(current_page)

    page = DashboardPage(title, level)
    level.add_page(page)

    token = _current_level.set(level)

    is_first_page = (
        manager.root_level is not None and
        len(manager.root_level.pages) == 1 and
        manager.root_level.child_level is None
    )

    try:
        if auto_start and is_first_page and not manager.is_running:
            await manager.start()

        yield page

    finally:
        _current_level.reset(token)
        level.remove_page(page)

        is_empty = (
            manager.root_level is not None and
            len(manager.root_level.pages) == 0
        )

        if auto_stop and is_empty and manager.is_running:
            await manager.stop()


__all__ = [
    "IDashboard",
    "DashboardPlugin",
    "dashboard_page",
    "get_dashboard",
]
