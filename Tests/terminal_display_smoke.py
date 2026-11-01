"""Native terminal display/navigation/host-input regressions.

Uses the isolated smoke-test app and synthetic files/account settings only.
No driver loading, process manipulation or real credentials.
"""
import ctypes as C
from ctypes import wintypes as W
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import threading
import time

from terminal_smoke import APP, OUT, K, U, Terminal, prepare

PROMPT = re.compile(r"\[(\d{2}:\d{2}:\d{2})\] AegisNT([^\r\n]*)\r?\n[╰+][^\r\n]*[>❯]\s*$")
MARKER = "Guest (local tools available; Account and Chat require login)"


def until(terminal, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = terminal.text()
        if predicate(data):
            return data
        if terminal.process.poll() is not None:
            break
        time.sleep(.05)
    raise AssertionError(terminal.text()[-8000:])


def command(terminal, line):
    terminal.send("cls\r")
    until(terminal, lambda data: PROMPT.search(data) and MARKER not in data)
    terminal.send(line + "\rwhoami\r")
    return until(terminal, lambda data: MARKER in data and PROMPT.search(data))


def run():
    prepare()
    results = []
    transcripts = []
    fixture = OUT / "directory fixture 中文"
    child = fixture / "child folder"
    child.mkdir(parents=True, exist_ok=True)
    (fixture / "alpha.txt").write_text("alpha", encoding="utf-8")
    (fixture / "中文文件.txt").write_text("中文", encoding="utf-8")
    (child / "inside.txt").write_text("child", encoding="utf-8")

    terminal = Terminal("--skip-login")
    try:
        initial = until(terminal, lambda data: PROMPT.search(data))
        first_time = PROMPT.search(initial).group(1)
        assert first_time == datetime.datetime.now().strftime("%H:%M:%S") or \
            first_time == (datetime.datetime.now() - datetime.timedelta(seconds=1)).strftime("%H:%M:%S")
        time.sleep(1.1)
        terminal.send("\r")
        until(terminal, lambda data: PROMPT.search(data) and PROMPT.search(data).group(1) != first_time)
        results.append("AegisNT case and local HH:mm:ss prefix; empty-line prompt refreshes time")

        data = command(terminal, "use File")
        assert "Path:" in data and "Path: -" not in data and "Modified" in data, data
        data = command(terminal, f'cd "{fixture}"')
        assert "alpha.txt" in data and "中文文件.txt" in data and "Unknown page" not in data, data
        transcripts.append(data)
        results.append("File entry automatically displays async directory; quoted cd reaches real files")

        for alias in ("dir", "ls", "list", "show"):
            data = command(terminal, alias)
            assert "alpha.txt" in data and "中文文件.txt" in data and "Modified" in data, data
        (fixture / "newly_created.txt").write_text("refresh", encoding="utf-8")
        assert "newly_created.txt" in command(terminal, "ls")
        results.append("show/ls/list/dir display files; ls reloads files created after initial listing")

        data = command(terminal, 'cd "child folder"')
        assert "inside.txt" in data and "child folder" in data, data
        data = command(terminal, "cd ..")
        assert "alpha.txt" in data and "directory fixture" in data, data
        assert "inside.txt" in command(terminal, "prev")
        assert "alpha.txt" in command(terminal, "forward")
        assert "directory fixture" in command(terminal, "pwd")
        assert "inside.txt" in command(terminal, 'dir "child folder"')
        assert "alpha.txt" in command(terminal, "up")
        results.append("relative cd, cd .., prev/forward, pwd, dir path, up preserve page navigation")

        data = command(terminal, "view protected")
        assert "[ProtectedFiles]" in data, data
        assert "alpha.txt" in command(terminal, "ls")
        data = command(terminal, "filter no-such-fixture-67fd")
        assert "No matching rows" in data and "alpha.txt" not in data, data
        assert "alpha.txt" in command(terminal, "filter")
        data = command(terminal, "help")
        assert "Navigation" in data and "ls [path]" in data and "run <command>" in data, data
        assert "home" in PROMPT.search(command(terminal, "back")).group(2)
        results.append("view commands show data; ls returns to Explorer; filters and common help work")

        # These views read normal user-mode state. Avoid driver-dependent pages.
        for page, expected in (("Settings", "Setting"),
                               ("ServiceManager", "Display Name"),
                               ("Network", "Protocol filter:")):
            data = command(terminal, "use " + page)
            assert expected in data, (page, data)
            for alias in ("show", "ls", "list", "dir", "refresh"):
                assert expected in command(terminal, alias), (page, alias)
            transcripts.append(data)
        results.append("Settings/ServiceManager/Network auto-display and shared aliases/refresh work")
    finally:
        terminal.close()

    # Deliberately leave a real PowerShell parent reading the keyboard while
    # starting the GUI-subsystem binary without CREATE_NEW_CONSOLE. Its child
    # must allocate a different console instead of borrowing this input buffer.
    pid_file = OUT / "display-child-pid.txt"
    pid_file.unlink(missing_ok=True)
    ps_script = OUT / "display-parent.ps1"
    ps_script.write_text(
        "$p = Start-Process -FilePath '" + str(APP / "AegisNT.exe").replace("'", "''") +
        "' -ArgumentList '--console' -PassThru -WindowStyle Hidden\n" +
        "[IO.File]::WriteAllText('" + str(pid_file).replace("'", "''") + "', [string]$p.Id)\n" +
        "[Console]::WriteLine('PARENT_INPUT_READY')\n" +
        "$null = [Console]::ReadLine()\n", encoding="utf-8-sig")
    config_path = APP / "Data" / "Config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["Account"].update(AutoLogin=True, SaveCredentials=True,
                             UserName="synthetic-test-user", Password="invalid-test-envelope")
    release_request = threading.Event()
    request_started = threading.Event()

    class SlowLogin(BaseHTTPRequestHandler):
        def do_POST(self):
            # No credential logging or successful authentication: deliberately
            # trigger the production six-second Qt transfer timeout.
            request_started.set()
            release_request.wait(12)
            self.close_connection = True
        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowLogin)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    config["LicenseServer"]["Address"] = f"http://127.0.0.1:{server.server_port}"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    parent = subprocess.Popen(["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
                               "-File", str(ps_script)], creationflags=subprocess.CREATE_NEW_CONSOLE,
                              startupinfo=startup, cwd=APP)
    terminal = Terminal.__new__(Terminal)
    terminal.input = terminal.output = None
    child_pid = None
    try:
        deadline = time.monotonic() + 12
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        child_pid = int(pid_file.read_text())

        class ChildProcess:
            def __init__(self, pid):
                self.pid = pid
                K.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
                K.OpenProcess.restype = W.HANDLE
                K.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
                K.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
                self.handle = K.OpenProcess(0x100000 | 0x1000 | 1, False, pid)
                assert self.handle
            def poll(self):
                status = W.DWORD()
                if not K.GetExitCodeProcess(self.handle, C.byref(status)):
                    raise C.WinError(C.get_last_error())
                return None if status.value == 259 else status.value
            def wait(self, timeout):
                end = time.monotonic() + timeout
                while self.poll() is None and time.monotonic() < end:
                    time.sleep(.05)
                if self.poll() is None:
                    raise subprocess.TimeoutExpired("test child", timeout)
                return self.poll()
            def terminate(self):
                K.TerminateProcess(self.handle, 1)

        terminal.process = ChildProcess(child_pid)
        terminal.attach(child_pid)
        data = terminal.wait("Continue [guest]")
        assert "Auto login as" not in data and "[A] Use saved sign-in" in data, data
        processes = (W.DWORD * 64)()
        count = K.GetConsoleProcessList(processes, 64)
        assert count <= 64 and parent.pid not in list(processes)[:count], list(processes)[:count]
        terminal.send("l\rtester\rsynthetic-password\r")
        assert request_started.wait(8), "login request never reached isolated timeout fixture"
        terminal.wait("Network error: Operation canceled", timeout=15)
        terminal.send("s\rwhoami\r")
        data = until(terminal, lambda data: MARKER in data and PROMPT.search(data))
        assert "More?" not in data and "synthetic-password" not in data, data
        assert parent.poll() is None, "parent input shell must survive"
        results.append("direct --console owns separate input while PowerShell parent reads; Operation canceled timeout -> S -> command input")
        transcripts.append(data)
    finally:
        if hasattr(terminal, "process"):
            terminal.close()
            K.CloseHandle(terminal.process.handle)
        if parent.poll() is None:
            parent.terminate()
            parent.wait(timeout=6)
        release_request.set()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    (OUT / "terminal-display-results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "terminal-display-transcript.txt").write_text("\n\n".join(transcripts), encoding="utf-8")
    for result in results:
        print("PASS:", result)


if __name__ == "__main__":
    run()
