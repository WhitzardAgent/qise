from __future__ import annotations

import struct
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_windows_qise_cli_processes_do_not_create_console_windows() -> None:
    source = (ROOT / "src-tauri/src/qise_cli.rs").read_text(encoding="utf-8")

    assert "std::os::windows::process::CommandExt" in source
    assert "const CREATE_NO_WINDOW: u32 = 0x08000000;" in source
    assert "command.creation_flags(CREATE_NO_WINDOW);" in source


def _png_corner_alphas(png: bytes) -> list[int]:
    width, height, bit_depth, color_type = struct.unpack_from(">IIBB", png, 16)
    assert bit_depth == 8
    assert color_type == 6

    chunks: list[bytes] = []
    position = 8
    while position < len(png):
        length = struct.unpack_from(">I", png, position)[0]
        kind = png[position + 4 : position + 8]
        data = png[position + 8 : position + 8 + length]
        position += length + 12
        if kind == b"IDAT":
            chunks.append(data)
        elif kind == b"IEND":
            break

    raw = zlib.decompress(b"".join(chunks))
    stride = width * 4
    rows: list[bytearray] = []
    previous = bytearray(stride)
    offset = 0

    def paeth(left: int, above: int, upper_left: int) -> int:
        estimate = left + above - upper_left
        left_distance = abs(estimate - left)
        above_distance = abs(estimate - above)
        upper_left_distance = abs(estimate - upper_left)
        if left_distance <= above_distance and left_distance <= upper_left_distance:
            return left
        if above_distance <= upper_left_distance:
            return above
        return upper_left

    for _ in range(height):
        filter_type = raw[offset]
        offset += 1
        row = bytearray(raw[offset : offset + stride])
        offset += stride
        for index in range(stride):
            left = row[index - 4] if index >= 4 else 0
            above = previous[index]
            upper_left = previous[index - 4] if index >= 4 else 0
            if filter_type == 1:
                row[index] = (row[index] + left) & 0xFF
            elif filter_type == 2:
                row[index] = (row[index] + above) & 0xFF
            elif filter_type == 3:
                row[index] = (row[index] + ((left + above) // 2)) & 0xFF
            elif filter_type == 4:
                row[index] = (row[index] + paeth(left, above, upper_left)) & 0xFF
            else:
                assert filter_type == 0
        rows.append(row)
        previous = row

    return [rows[0][3], rows[0][-1], rows[-1][3], rows[-1][-1]]


def test_windows_icon_frames_have_transparent_corners() -> None:
    icon = (ROOT / "src-tauri/icons/icon.ico").read_bytes()
    frame_count = struct.unpack_from("<H", icon, 4)[0]

    assert frame_count > 0
    for index in range(frame_count):
        size, offset = struct.unpack_from("<II", icon, 6 + index * 16 + 8)
        frame = icon[offset : offset + size]
        assert frame.startswith(b"\x89PNG\r\n\x1a\n")
        assert _png_corner_alphas(frame) == [0, 0, 0, 0]
