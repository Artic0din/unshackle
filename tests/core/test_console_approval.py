from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any

from unshackle.core import console
from unshackle.core.approval import ApprovalNotice


def test_concurrent_approvals_clear_only_their_own_display(monkeypatch) -> None:
    displays: list[Any] = []

    class FakeLive:
        def __init__(self, renderable, *_args, **_kwargs) -> None:
            self.renderable = renderable
            self.stopped = False
            displays.append(self)

        def start(self) -> None:
            return None

        def update(self, renderable, **_kwargs) -> None:
            self.renderable = renderable

        def stop(self) -> None:
            self.stopped = True

    monkeypatch.setattr(console, "SyncLive", FakeLive)
    monkeypatch.setattr(console, "console", SimpleNamespace(is_terminal=True))
    monkeypatch.setattr(console, "_approval_handler", None)
    shown = threading.Barrier(3)
    clear = [threading.Event(), threading.Event()]
    cleared = [threading.Event(), threading.Event()]

    def show(index: int, message: str) -> None:
        console.show_approval(ApprovalNotice(message))
        shown.wait(timeout=5)
        assert clear[index].wait(timeout=5)
        console.show_approval(None)
        cleared[index].set()

    threads = [
        threading.Thread(target=show, args=(index, message), daemon=True)
        for index, message in enumerate(("First", "Second"))
    ]
    for thread in threads:
        thread.start()
    shown.wait(timeout=5)
    try:
        assert len(displays) == 1
        assert len(displays[0].renderable.renderables) == 2
        clear[0].set()
        assert cleared[0].wait(timeout=5)
        assert not displays[0].stopped
        assert len(displays[0].renderable.renderables) == 1
    finally:
        for event in clear:
            event.set()
        for thread in threads:
            thread.join(timeout=5)
    assert displays[0].stopped
