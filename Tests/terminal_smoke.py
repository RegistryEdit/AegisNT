"""Win32 integration tests against the built terminal in an isolated app folder.

Never sends global keystrokes, uses real credentials, or loads test drivers.
Run: python Tests/terminal_smoke.py
"""
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "terminal-regression"
APP = OUT / "app"
K = C.WinDLL("kernel32", use_last_error=True)
U = C.WinDLL("user32", use_last_error=True)

class COORD(C.Structure):
    _fields_ = [("X", C.c_short), ("Y", C.c_short)]
class RECT(C.Structure):
    _fields_ = [("Left", C.c_short), ("Top", C.c_short), ("Right", C.c_short), ("Bottom", C.c_short)]
class CSBI(C.Structure):
    _fields_ = [("size", COORD), ("cursor", COORD), ("attr", W.WORD), ("window", RECT), ("maxsize", COORD)]
class KEY(C.Structure):
    _fields_ = [("down", W.BOOL), ("repeat", W.WORD), ("vk", W.WORD),
                ("scan", W.WORD), ("char", W.WCHAR), ("mod", W.DWORD)]
class EVENT(C.Union):
    _fields_ = [("key", KEY), ("padding", C.c_byte * 20)]
class INPUT(C.Structure):
    _fields_ = [("kind", W.WORD), ("event", EVENT)]
class CHAR(C.Union):
    _fields_ = [("wide", W.WCHAR), ("byte", C.c_char)]
class CELL(C.Structure):
    _fields_ = [("char", CHAR), ("attr", W.WORD)]

K.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
K.CreateFileW.restype = W.HANDLE
K.CloseHandle.argtypes = [W.HANDLE]
K.AttachConsole.argtypes = [W.DWORD]
K.GetConsoleWindow.restype = W.HWND
K.GetConsoleScreenBufferInfo.argtypes = [W.HANDLE, C.POINTER(CSBI)]
K.ReadConsoleOutputCharacterW.argtypes = [W.HANDLE, W.LPWSTR, W.DWORD, COORD, C.POINTER(W.DWORD)]
K.ReadConsoleOutputW.argtypes = [W.HANDLE, C.POINTER(CELL), COORD, COORD, C.POINTER(RECT)]
K.WriteConsoleInputW.argtypes = [W.HANDLE, C.POINTER(INPUT), W.DWORD, C.POINTER(W.DWORD)]
U.ShowWindow.argtypes = [W.HWND, C.c_int]

def prepare(language="en_US"):
    APP.mkdir(parents=True, exist_ok=True)
    for src in [ROOT / "Bin" / "AegisNT.exe", *(ROOT / "Bin").glob("*.dll")]:
        # Windows may briefly retain the image section after a test process
        # reports exit. Retry only sharing violations, with a bounded deadline.
        deadline = time.monotonic() + 3
        while True:
            try:
                shutil.copy2(src, APP / src.name)
                break
            except PermissionError as error:
                if error.winerror != 32 or time.monotonic() >= deadline:
                    raise
                time.sleep(.1)
    for directory in ("platforms", "styles", "imageformats"):
        src = ROOT / "Bin" / directory
        if src.exists():
            shutil.copytree(src, APP / directory, dirs_exist_ok=True)
    (APP / "Data").mkdir(exist_ok=True)
    for name in ("en_US.json", "zh_CN.json"):
        shutil.copy2(ROOT / "Data" / name, APP / "Data" / name)
    config = {
        "Application": {"Language": language, "ConsoleVisible": False, "Width": 1200, "Height": 800},
        "Account": {"IsLoggedIn": True, "UserName": "stale-test-user", "Token": "invalid-test-token", "AutoLogin": False, "SaveCredentials": False},
        "Drivers": {"AutoLoad": False, "Paths": []},
        "Modules": {"AutoLoad": False, "Paths": []},
        "LicenseServer": {"Address": "http://127.0.0.1:1"},
    }
    (APP / "Data" / "Config.json").write_text(json.dumps(config), encoding="utf-8")

class Terminal:
    def __init__(self, *args, creationflags=subprocess.CREATE_NEW_CONSOLE):
        self.process = subprocess.Popen([str(APP / "AegisNT.exe"), "--console", *args],
                                        cwd=APP, creationflags=creationflags)
        self.input = self.output = None
        self.attach(self.process.pid)
    def attach(self, pid):
        K.FreeConsole()
        until = time.monotonic() + 8
        while not K.AttachConsole(pid):
            if self.process.poll() is not None or time.monotonic() > until:
                raise RuntimeError(f"cannot attach to test console: {C.get_last_error()}")
            time.sleep(.05)
        U.ShowWindow(K.GetConsoleWindow(), 0)
        self.input = K.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
        self.output = K.CreateFileW("CONOUT$", 0xC0000000, 3, None, 3, 0, None)
    def text(self):
        info = CSBI()
        if not K.GetConsoleScreenBufferInfo(self.output, C.byref(info)):
            return ""
        start = max(0, info.cursor.Y - 350)
        height = min(info.size.Y - start, info.cursor.Y - start + 2)
        cells = (CELL * (info.size.X * height))()
        rect = RECT(0, start, info.size.X - 1, start + height - 1)
        if not K.ReadConsoleOutputW(self.output, cells, COORD(info.size.X, height), COORD(0, 0), C.byref(rect)):
            raise C.WinError(C.get_last_error())
        # ReadConsoleOutputCharacterW returns characters, not display cells;
        # splitting that string at the buffer width breaks CJK row boundaries.
        lines = []
        for y in range(height):
            line = "".join(cell.char.wide or " " for cell in cells[y*info.size.X:(y+1)*info.size.X]
                           if not (cell.attr & 0x0200))
            lines.append(line.rstrip())
        return "\n".join(lines)
    def wait(self, text, timeout=8):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            data = self.text()
            if text in data: return data
            if self.process.poll() is not None: break
            time.sleep(.05)
        raise AssertionError(f"missing {text!r}; exit={self.process.poll()}\n{self.text()[-6000:]}")
    def key(self, vk, char="\0", mod=0):
        events = (INPUT * 2)()
        for i in range(2):
            events[i].kind = 1
            events[i].event.key = KEY(i == 0, 1, vk, 0, char, mod)
        n = W.DWORD()
        if not K.WriteConsoleInputW(self.input, events, 2, C.byref(n)):
            raise C.WinError(C.get_last_error())
    def send(self, text):
        # Send UTF-16 units; pasted lines stay in the native input buffer.
        units = text.encode("utf-16-le")
        for i in range(0, len(units), 2):
            char = chr(int.from_bytes(units[i:i+2], "little"))
            self.key(13 if char == "\r" else 0, char)
    def close(self):
        if self.process.poll() is None:
            self.send("exit\r")
            try: self.process.wait(timeout=6)
            except subprocess.TimeoutExpired: self.process.terminate(); self.process.wait(timeout=4)
        for handle in (self.input, self.output):
            if handle: K.CloseHandle(handle)
        K.FreeConsole()

def run():
    prepare()
    results = []
    terminal = Terminal()
    try:
        terminal.wait("Continue [guest]")
        terminal.send("s\r\nwhoami\r\npages\r\n")
        data = terminal.wait("HotKeys")
        assert "Guest session" in data and "Sign in" in data
        assert "Password:" not in data and "Signing in" not in data
        results.append("skip at first prompt; pasted commands preserved; stale identity cleared")
        terminal.send("use Account\r")
        terminal.wait("This page requires sign-in")
        terminal.send("use Module\r")
        terminal.wait("Ambiguous page name")
        results.append("guest account gate; ambiguous page names rejected")
        terminal.send("versio")
        terminal.key(9, "\t")
        terminal.key(13, "\r")
        terminal.wait("AegisNT 3.6.2")
        terminal.send("vers")
        terminal.wait("❯ vers")
        terminal.key(38)
        time.sleep(.15)
        assert terminal.text().rstrip().endswith("❯ version"), terminal.text()[-300:]
        terminal.key(40)
        terminal.wait("❯ vers")
        terminal.key(27)
        terminal.send("versiox")
        terminal.key(37)
        terminal.key(46)
        terminal.send("n\r")
        data = terminal.wait("version", timeout=3)
        results.append("Tab completion; Up/Down prefix history draft; cursor insertion and Delete; Escape")
        terminal.send("login\r")
        terminal.wait("Continue [guest]")
        terminal.send("l\r\ntester\r\n")
        terminal.wait("Password:")
        terminal.send("private-test-value")
        terminal.key(27)
        terminal.send("s\rwhoami\r")
        data = terminal.wait("Type 'login' whenever")
        assert "private-test-value" not in data
        assert "Signed in as" not in data
        results.append("login cancellation returns to guest; passwords masked; no false signed-in message")
        (OUT / "terminal-transcript.txt").write_text(terminal.text(), encoding="utf-8")
        terminal.send("exit\r")
        assert terminal.process.wait(timeout=6) == 0
        results.append("normal exit joins input worker cleanly")
    finally:
        terminal.close()
    terminal = Terminal("--skip-login")
    try:
        data = terminal.wait("Guest session ready (--skip-login)")
        assert "Continue [guest]" not in data and "Signing in" not in data
        terminal.send("whoami\r")
        terminal.wait("Guest (local tools available")
        terminal.key(0x44, "\x04", 8)
        assert terminal.process.wait(timeout=6) == 0
        results.append("--skip-login bypasses gate; Ctrl+D empty-line exit")
    finally:
        terminal.close()
    (OUT / "terminal-smoke-results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    for result in results: print("PASS:", result)

if __name__ == "__main__":
    run()
