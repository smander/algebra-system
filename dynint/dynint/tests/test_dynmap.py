import json
from pathlib import Path

import pytest

from dynint import dynmap, mapfile
from dynint import cli

SPACECRAFT = Path(__file__).resolve().parents[1] / "spacecraft_server_linux_x86"


@pytest.fixture(scope="session")
def spacecraft_map() -> dict:
    mapping = dynmap.generate_map(
        binary_path=SPACECRAFT,
        include_bytes=True,
        include_dwarf=True,
    )
    # basic schema sanity check before returning
    assert "functions" in mapping and mapping["functions"], "expected functions in mapping"
    assert "callsites" in mapping, "expected callsites list in mapping"
    return mapping


@pytest.fixture(scope="session")
def spacecraft_mapdata(spacecraft_map) -> mapfile.MapData:
    # round-trip via mapfile helpers to ensure JSON encoding/decoding stays consistent
    payload = json.loads(json.dumps(spacecraft_map))
    map_data = mapfile.MapData.from_json(payload)
    assert map_data.functions, "MapData should expose function entries"
    return map_data


def test_dynmap_discovers_recvfrom_call(spacecraft_map):
    callsites = spacecraft_map["callsites"]
    symbols = {str(cs.get("target")) for cs in callsites if cs.get("target")}
    versions = {sv.get("qualified") for sv in spacecraft_map.get("symbol_versions", [])}
    assert any("recvfrom" in symbol for symbol in symbols | versions), "recvfrom should be recorded in map"


def test_mapdata_lookup_by_address(spacecraft_mapdata):
    first_fn = spacecraft_mapdata.functions[0]
    target = spacecraft_mapdata.find_function_by_addr(first_fn.addr)
    assert target is not None
    assert target.addr == first_fn.addr


def test_cli_map_roundtrip(tmp_path: Path):
    output = tmp_path / "map.json"
    exit_code = cli.main([
        "map",
        str(SPACECRAFT),
        "--output",
        str(output),
        "--bytes",
    ])
    assert exit_code == 0
    data = json.loads(output.read_text())
    assert "binary" in data and data["binary"]["path"].endswith("spacecraft_server_linux_x86")
