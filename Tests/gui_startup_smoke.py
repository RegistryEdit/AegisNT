"""No-argument GUI startup regression against the isolated test app."""
import ctypes as C
from ctypes import wintypes as W
import json
import subprocess
import time
from terminal_smoke import APP, OUT, U, prepare


def run():
    prepare()
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen([str(APP / "AegisNT.exe")], cwd=APP, startupinfo=startup)
    windows = []
    callback_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    U.EnumWindows.argtypes = [callback_type, W.LPARAM]
    U.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    U.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]

    @callback_type
    def collect(hwnd, _):
        pid = W.DWORD()
        U.GetWindowThreadProcessId(hwnd, C.byref(pid))
        if pid.value == process.pid:
            windows.append(hwnd)
        return True

    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            assert process.poll() is None, f"GUI exited during startup: {process.returncode}"
            time.sleep(.1)
        U.EnumWindows(collect, 0)
        assert windows, "GUI never created a native window"
        result = {"passed": True, "seconds": 5, "windows": len(windows),
                  "scenario": "no --console argument; isolated config; no startup crash"}
        (OUT / "gui-startup-results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print("PASS: no-argument GUI stays alive for five seconds and creates native windows")
    finally:
        for hwnd in windows: U.PostMessageW(hwnd, 0x10, 0, 0)
        if process.poll() is None:
            try: process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=4)


if __name__ == "__main__":
    run()
