import sys
import types
from pathlib import Path

import pytest

from dynint import dynmap, mapfile


class _FakeInvalidOperationError(Exception):
    pass


# Provide a minimal stub for the `frida` module so the backend can be imported without the real dependency.
class _FakeScript:
    def __init__(self):
        self.handlers = {}

    def on(self, event, handler):
        self.handlers[event] = handler

    def load(self):  # pragma: no cover - no runtime behaviour in unit test
        pass

    def unload(self):  # pragma: no cover
        pass


class _FakeSession:
    def __init__(self):
        self.created_scripts = []

    def create_script(self, source):
        script = _FakeScript()
        script.source = source
        self.created_scripts.append(script)
        return script

    def detach(self):  # pragma: no cover
        pass


class _FakeFrida(types.SimpleNamespace):
    InvalidOperationError = _FakeInvalidOperationError

    def __init__(self):
        super().__init__()
        self.attach_calls = []

    def attach(self, pid):
        self.attach_calls.append(pid)
        return _FakeSession()

    def spawn(self, argv):  # pragma: no cover
        return 4242

    def resume(self, pid):  # pragma: no cover
        pass


@pytest.fixture(scope="session")
def fake_frida_module():
    fake = _FakeFrida()
    sys.modules["frida"] = fake
    return fake


@pytest.fixture(scope="session")
def spacecraft_mapdata() -> mapfile.MapData:
    binary = Path(__file__).resolve().parents[1] / "spacecraft_server_linux_x86"
    mapping = dynmap.generate_map(binary_path=binary, include_bytes=True)
    return mapfile.MapData.from_json(mapping)


def test_frida_backend_builds_script(fake_frida_module, spacecraft_mapdata, monkeypatch):
    from dynint.dyntrace import frida_backend

    backend = frida_backend.FridaBackend(
        mapping=spacecraft_mapdata,
        libs=[],
        functions=[],
        callsites=[],
        output_path=None,
        sample=None,
        since=None,
        duration=0.0,
    )

    # Skip runtime rebasing for the unit test
    monkeypatch.setattr(frida_backend.FridaBackend, "_prepare_runtime_context", lambda self: None)
    backend._runtime_callsites = []
    script_source = backend._build_script()

    assert "recvfrom" in script_source, "Frida script should include target symbol"
    assert backend.target_functions, "Expected at least one function hook"

    # Exercise stop() without starting a session
    backend.stop()
