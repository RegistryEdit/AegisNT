"""Native Win32 integration: snapshot paging, pipelines, hints and real captures.

Uses the isolated app and fixtures only. Screenshots are captured from the real
console HWND, never rendered from a transcript. Run after build_ui.cmd.
"""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import time

from terminal_smoke import APP, ROOT, OUT, K, U, COORD, RECT, CSBI, CELL, Terminal, prepare
from terminal_display_smoke import PROMPT, MARKER, until

REPORT = ROOT / "out" / "terminal-modern"
REPORT.mkdir(parents=True, exist_ok=True)
K.SetConsoleScreenBufferSize.argtypes = [W.HANDLE, COORD]
K.SetConsoleWindowInfo.argtypes = [W.HANDLE, W.BOOL, C.POINTER(RECT)]
K.GetConsoleMode.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
K.SetConsoleMode.argtypes = [W.HANDLE, W.DWORD]


def dimensions(terminal):
    info = CSBI()
    assert K.GetConsoleScreenBufferInfo(terminal.output, C.byref(info))
    return info


def resize(terminal, columns, rows=34):
    info = dimensions(terminal)
    small = RECT(0, 0, min(columns, info.window.Right - info.window.Left + 1) - 1,
                 min(rows, info.window.Bottom - info.window.Top + 1) - 1)
    assert K.SetConsoleWindowInfo(terminal.output, True, C.byref(small)), C.get_last_error()
    assert K.SetConsoleScreenBufferSize(terminal.output, COORD(columns, info.size.Y)), C.get_last_error()
    rect = RECT(0, 0, columns - 1, rows - 1)
    assert K.SetConsoleWindowInfo(terminal.output, True, C.byref(rect)), C.get_last_error()
    terminal.key(0x4C, "\x0c", 8)
    until(terminal, lambda s: PROMPT.search(s))
    info = dimensions(terminal)
    assert info.size.X == columns and info.window.Right - info.window.Left + 1 == columns


def command_local(terminal, text, chinese=False):
    marker = "访客（" if chinese else "".join(MARKER.split())
    present = lambda s: marker in "".join(s.split())
    terminal.send("cls\r")
    until(terminal, lambda s: PROMPT.search(s) and not present(s))
    terminal.send(text + "\rwhoami\r")
    return until(terminal, lambda s: present(s) and PROMPT.search(s))


def command(terminal, text):
    return command_local(terminal, text)


def capture_window(terminal, filename, hwnd=None):
    """PrintWindow with a visible-console BitBlt fallback; restore visibility."""
    from PIL import Image, ImageStat
    U.SetProcessDPIAware()
    G = C.WinDLL("gdi32", use_last_error=True)
    U.GetWindowRect.argtypes = [W.HWND, C.POINTER(W.RECT)]
    U.GetWindowDC.argtypes = [W.HWND]; U.GetWindowDC.restype = W.HDC
    U.ReleaseDC.argtypes = [W.HWND, W.HDC]
    U.PrintWindow.argtypes = [W.HWND, W.HDC, W.UINT]
    U.SetWindowPos.argtypes = [W.HWND, W.HWND, C.c_int, C.c_int, C.c_int, C.c_int, W.UINT]
    G.CreateCompatibleDC.argtypes = [W.HDC]; G.CreateCompatibleDC.restype = W.HDC
    G.CreateCompatibleBitmap.argtypes = [W.HDC, C.c_int, C.c_int]; G.CreateCompatibleBitmap.restype = W.HBITMAP
    G.SelectObject.argtypes = [W.HDC, W.HGDIOBJ]; G.SelectObject.restype = W.HGDIOBJ
    G.BitBlt.argtypes = [W.HDC, C.c_int, C.c_int, C.c_int, C.c_int, W.HDC, C.c_int, C.c_int, W.DWORD]
    G.DeleteDC.argtypes = [W.HDC]; G.DeleteObject.argtypes = [W.HGDIOBJ]

    class BIH(C.Structure):
        _fields_ = [("size", W.DWORD), ("width", W.LONG), ("height", W.LONG),
                    ("planes", W.WORD), ("bits", W.WORD), ("compression", W.DWORD),
                    ("sizeImage", W.DWORD), ("xppm", W.LONG), ("yppm", W.LONG),
                    ("used", W.DWORD), ("important", W.DWORD)]
    G.GetDIBits.argtypes = [W.HDC, W.HBITMAP, W.UINT, W.UINT, W.LPVOID, C.POINTER(BIH), W.UINT]
    hwnd = hwnd or K.GetConsoleWindow()
    was_visible = U.IsWindowVisible(hwnd)
    dc = mem = bitmap = old = None
    try:
        U.ShowWindow(hwnd, 4)  # SW_SHOWNOACTIVATE: no focus or global keystrokes.
        U.SetWindowPos(hwnd, W.HWND(0), 30, 30, 0, 0, 0x0011)
        time.sleep(.25)
        rect = W.RECT(); assert U.GetWindowRect(hwnd, C.byref(rect))
        width, height = rect.right - rect.left, rect.bottom - rect.top
        dc = U.GetWindowDC(hwnd); mem = G.CreateCompatibleDC(dc)
        bitmap = G.CreateCompatibleBitmap(dc, width, height)
        old = G.SelectObject(mem, bitmap)
        ok = U.PrintWindow(hwnd, mem, 2)
        header = BIH(C.sizeof(BIH), width, -height, 1, 32, 0, 0, 0, 0, 0, 0)
        buffer = C.create_string_buffer(width * height * 4)

        def pixels():
            G.SelectObject(mem, old)
            assert G.GetDIBits(dc, bitmap, 0, height, buffer, C.byref(header), 0)
            G.SelectObject(mem, bitmap)
            return Image.frombuffer("RGB", (width, height), buffer.raw, "raw", "BGRX", 0, 1)

        image = pixels()
        # Avoid accepting an empty capture; examine the client area, not frame.
        if not ok or max(ImageStat.Stat(image.crop((10, 40, width - 10, height - 10))).stddev) < 3:
            assert G.BitBlt(mem, 0, 0, width, height, dc, 0, 0, 0x00CC0020)
            image = pixels()
        assert max(ImageStat.Stat(image.crop((10, 40, width - 10, height - 10))).stddev) > 3, "blank native console capture"
        image.save(REPORT / filename)
        return {"file": filename, "width": width, "height": height, "capture": "native console HWND"}
    finally:
        if old and mem: G.SelectObject(mem, old)
        if bitmap: G.DeleteObject(bitmap)
        if mem: G.DeleteDC(mem)
        if dc: U.ReleaseDC(hwnd, dc)
        if not was_visible: U.ShowWindow(hwnd, 0)


def yellow_cells(terminal):
    info = dimensions(terminal)
    height = min(info.cursor.Y + 1, info.size.Y)
    cells = (CELL * (info.size.X * height))()
    rect = RECT(0, 0, info.size.X - 1, height - 1)
    assert K.ReadConsoleOutputW(terminal.output, cells, COORD(info.size.X, height), COORD(0, 0), C.byref(rect))
    return sum(1 for cell in cells if cell.attr & 0x0F in (6, 14) and cell.char.wide not in (" ", "\0"))


def run():
    # The automation host exports NO_COLOR=1. Exercise color explicitly in
    # test children; the final matrix separately verifies NO_COLOR behavior.
    os.environ.pop("NO_COLOR", None)
    os.environ.pop("AEGISNT_NO_COLOR", None)
    prepare()
    results, screenshots, transcripts = [], [], []
    fixture = REPORT / ("fixture 中文 " + str(time.time_ns()))
    fixture.mkdir()
    for i in range(1, 46):
        (fixture / f"entry_{i:02}_alpha.txt").write_text(f"row {i}\n", encoding="utf-8")
    (fixture / "documents").mkdir()
    (fixture / "中文日志.log").write_text("中文", encoding="utf-8")
    (fixture / "cafe\u0301.txt").write_text("combining", encoding="utf-8")
    (fixture / ("long_" + "x" * 90 + "_needle.txt")).write_text("long", encoding="utf-8")
    total = len(list(fixture.iterdir()))
    t = Terminal("--skip-login")
    try:
        until(t, lambda s: PROMPT.search(s))
        command(t, "use File")
        data = command(t, f'cd "{fixture}"')
        assert f"{total} matched / {total} total" in data and "Rows 1-20" in data, data
        assert "Rows 21-40" in command(t, "next-page")
        assert f"Rows 41-{total}" in command(t, "show 3")
        assert "Page must be in 1..3" in command(t, "show 4")
        assert f"Rows 41-{total}" in command(t, "show")
        assert "Rows 21-40" in command(t, "prev-page")
        assert f"Rows 1-{total}" in command(t, "show all")
        results.append("real File snapshot: 20-row pages, last page, range error preserves page, prev-page, show all")

        command(t, "show 1")
        data = command(t, 'show|grep -n "ENTRY_" | find "45"')
        found = re.search(r"^\s*(\d+): .*entry_45_alpha.txt", data, re.M)
        assert found and f"1 matched / {total} searched" in data, data
        number = int(found[1])
        assert "entry_45_alpha.txt" in command(t, f"detail {number}")
        data = command(t, 'find "needle"')
        assert "_needle.txt" in data and f"1 matched / {total} searched" in data, data
        assert yellow_cells(t) > 0, "search keyword has no native color attributes"
        data = command(t, 'show | find "中文"')
        assert "中文日志.log" in data and f"1 matched / {total} searched" in data, data
        data = command(t, 'show | find "alpha|literal"')
        assert "No matching text" in data, data
        assert "Empty pipeline stage" in command(t, "show || find alpha")
        assert "After | use find" in command(t, "show | unknown alpha")
        assert "Page must be" in command(t, "show 999 | find alpha")
        data = command(t, 'ls "missing-directory-087e" | find alpha')
        assert "folder does not exist" in data and "Find / alpha" not in data, data
        data = command(t, 'help | find "snapshot"')
        assert "output line numbers" in data and re.search(r"^\s*\d+:.*snapshot", data, re.M), data
        data = command(t, "detail 1 | find Name")
        assert "output line numbers" in data, data
        results.append("pipes: quoted/adjacent/chained grep/find, Unicode and case-insensitive search, source row identity, logical text line numbers, native keyword color, parse errors")

        (fixture / "new_after_snapshot.txt").write_text("new", encoding="utf-8")
        assert "0 matched" in command(t, 'show | find "new_after_snapshot"')
        assert "1 matched" in command(t, 'ls | find "new_after_snapshot"')
        assert "Rows 1-20" in command(t, "show")
        command(t, "show 2")
        assert "Rows 1-20" in command(t, "refresh")
        data = command(t, "filter entry_45")
        assert "1 matched" in data and "Rows 1-1" in data, data
        assert yellow_cells(t) > 0, "filter keyword has no color"
        assert "entry_45_alpha.txt" in command(t, "detail 1")
        command(t, "filter")
        assert "Rows 1-20" in command(t, "show")
        results.append("snapshot stable after disk mutation; ls reload and refresh reset; filter reindexes detail and highlights")

        t.send("sh")
        until(t, lambda s: s.rstrip().endswith("❯ show [Tab]"))
        t.key(13, "\r")
        until(t, lambda s: "Unknown command: sh" in s and PROMPT.search(s))
        t.send("cls\r")
        until(t, lambda s: PROMPT.search(s) and "Unknown command" not in s)
        t.send("sh")
        t.key(9, "\t")
        until(t, lambda s: s.rstrip().endswith("❯ show all [Tab]"))
        t.key(9, "\t")
        until(t, lambda s: "Tab  show  /  show all" in s)
        t.key(27)
        t.send("ls | gr")
        until(t, lambda s: "grep [Tab]" in s)
        t.key(9, "\t")
        t.send(' "entry_21"\r')
        until(t, lambda s: "entry_21_alpha.txt" in s and PROMPT.search(s))
        t.send("draft中文e\u0301")
        t.key(0x4C, "\x0c", 8)
        until(t, lambda s: s.rstrip().endswith("❯ draft中文e\u0301"))
        t.key(27)
        t.send("login\rl\rtester\r")
        t.wait("Password:")
        t.send("show-super-secret")
        t.key(9, "\t")
        time.sleep(.1)
        assert "show-super-secret" not in t.text() and "[Tab]" not in t.text(), t.text()
        t.key(27); t.send("s\r")
        until(t, lambda s: PROMPT.search(s))
        results.append("ghost hint never auto-submits; Tab candidate list and pipe completion; Ctrl+L preserves Unicode draft; password never previews/completes")

        for columns in (40, 80, 120):
            resize(t, columns)
            data = command(t, "show 3")
            assert PROMPT.search(data), data  # exactly two physical prompt lines
            data = command(t, 'show | find "needle"')
            assert "_needle.txt" in "".join(data.split()), data
            assert "folder" in command(t, "help refresh")
            data = command(t, "help all")
            assert "Page actions" in data or columns == 40, data
            # Short native output leaves space to inspect the prompt and input.
            data = command(t, 'show | find "entry_45"')
            if columns == 120:
                data = command(t, "show 3")
            t.send("show | gr")
            until(t, lambda s: "grep [Tab]" in s)
            screenshots.append(capture_window(t, f"terminal-{columns}-en.png"))
            transcripts.append({"columns": columns, "language": "en_US", "text": t.text()})
            t.key(27)
            mode = W.DWORD(); assert K.GetConsoleMode(t.output, C.byref(mode))
            assert K.SetConsoleMode(t.output, mode.value & ~4)
            try:
                t.key(0x4C, "\x0c", 8)
                until(t, lambda s: s.rstrip().endswith("+- >"))
                data = command(t, "show 3")
                assert "╰" not in data and "─" not in data and "…" not in data, data
            finally:
                K.SetConsoleMode(t.output, mode.value)
                t.key(0x4C, "\x0c", 8)
                until(t, lambda s: PROMPT.search(s))
        results.append("40/80/120 native widths: two physical prompt lines, long paths/CJK/combining names, ASCII fallback, real HWND screenshots")
        # A clean product capture, separate from the synchronization transcripts.
        resize(t, 120, 24)
        command(t, f'cd "{ROOT / "Source" / "Tui"}"')
        t.send("cls\r")
        until(t, lambda s: PROMPT.search(s) and MARKER not in s)
        t.send('ls | grep -n ".h"\r')
        until(t, lambda s: "matched /" in s and PROMPT.search(s))
        t.send("show | gr")
        until(t, lambda s: "grep [Tab]" in s)
        screenshots.append(capture_window(t, "terminal-preview.png"))
        t.key(27)
    finally:
        t.close()

    prepare("zh_CN")
    t = Terminal("--skip-login")
    try:
        until(t, lambda s: PROMPT.search(s))
        command_local(t, "use File", True)
        command_local(t, f'cd "{fixture}"', True)
        for columns in (40, 80, 120):
            resize(t, columns)
            data = command_local(t, 'show | find "中文"', True)
            assert "1 行匹配" in data and "中文日志.log" in data, data
            assert "访客" in PROMPT.search(data).group(2), data
        command_local(t, "show 3", True)
        screenshots.append(capture_window(t, "terminal-120-zh.png"))
        transcripts.append({"columns": 120, "language": "zh_CN", "text": t.text()})
        results.append("Chinese common UI and find summaries at all three native widths")
    finally:
        t.close()

    prepare()
    previous = os.environ.get("NO_COLOR")
    os.environ["NO_COLOR"] = "1"
    try:
        t = Terminal("--skip-login")
    finally:
        if previous is None: os.environ.pop("NO_COLOR", None)
        else: os.environ["NO_COLOR"] = previous
    try:
        until(t, lambda s: PROMPT.search(s))
        command(t, "use File")
        command(t, f'cd "{fixture}"')
        for columns in (40, 80, 120):
            resize(t, columns)
            data = command(t, 'show | find "entry_21"')
            assert "1 matched" in data and yellow_cells(t) == 0, data
        t.send("sh")
        until(t, lambda s: "[Tab: show]" in s)
        t.key(27)
        results.append("NO_COLOR at 40/80/120: readable numbered matches, no yellow ANSI, explicit plain-text completion hint")
    finally:
        t.close()

    (REPORT / "modern-results.json").write_text(json.dumps({"results": results, "screenshots": screenshots, "fixture": str(fixture)}, ensure_ascii=False, indent=2), encoding="utf-8")
    (REPORT / "modern-transcripts.json").write_text(json.dumps(transcripts, ensure_ascii=False, indent=2), encoding="utf-8")
    for result in results: print("PASS:", result)


if __name__ == "__main__":
    run()
