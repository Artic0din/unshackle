"""DASH tracks with metadata-only PSSH boxes stay clear."""

from __future__ import annotations

import struct
import sys
from functools import partial
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pywidevine.license_protocol_pb2 import WidevinePsshData
from pywidevine.pssh import PSSH

from unshackle.core import binaries
from unshackle.core.constants import DOWNLOAD_LICENCE_ONLY
from unshackle.core.drm import Widevine
from unshackle.core.manifests import DASH
from unshackle.core.tracks import Audio
from unshackle.core.tracks.track import DownloadContext

MANIFEST_URL = "https://example.test/manifest.mpd"
MPD = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static" mediaPresentationDuration="PT1S">
  <Period id="0" duration="PT1S">
    <AdaptationSet contentType="audio" mimeType="audio/mp4" lang="en">
      <Representation id="a0" codecs="mp4a.40.2" bandwidth="128000">
        <SegmentTemplate timescale="1" duration="1" initialization="init.mp4" media="$Number$.m4s"/>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
"""


def pssh_without_kid() -> bytes:
    return PSSH.new(
        system_id=PSSH.SystemId.Widevine,
        init_data=WidevinePsshData(content_id=b"metadata-only").SerializeToString(),
    ).dump()


def tenc_without_kid() -> bytes:
    body = b"\0\0\0\0\0\0\1\x10" + UUID(int=0).bytes
    return struct.pack(">I4s", len(body) + 8, b"tenc") + body


def download_with_init(init_data: bytes, tmp_path: Path, monkeypatch: Any) -> Audio:
    track = DASH.from_text(MPD, MANIFEST_URL).to_tracks().audio[0]
    monkeypatch.setattr(binaries, "FFProbe", Path(sys.executable))
    monkeypatch.setattr(
        DASH,
        "get_period_segments",
        staticmethod(lambda **_: (init_data, [("https://example.test/1.m4s", None)], 1, [1], None)),
    )
    ctx = DownloadContext(
        save_path=tmp_path / "audio.mp4",
        save_dir=tmp_path / "audio_segments",
        progress=partial(lambda **_: None),
        license_widevine=lambda *_args, **_kwargs: pytest.fail("clear audio requested a licence"),
    )
    DOWNLOAD_LICENCE_ONLY.set()
    try:
        DASH.download_track(track, ctx)
    finally:
        DOWNLOAD_LICENCE_ONLY.clear()
    return track


def test_kidless_pssh_does_not_mark_clear_audio_as_encrypted(tmp_path: Path, monkeypatch: Any) -> None:
    track = download_with_init(pssh_without_kid(), tmp_path, monkeypatch)

    assert not track.drm


def test_kidless_pssh_still_fails_when_tenc_marks_encryption(tmp_path: Path, monkeypatch: Any) -> None:
    with pytest.raises(Widevine.Exceptions.KIDNotFound):
        download_with_init(pssh_without_kid() + tenc_without_kid(), tmp_path, monkeypatch)
