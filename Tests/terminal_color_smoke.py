"""Semantic color integration and real terminal screenshots (sequential).

--windows-terminal additionally launches one dedicated Windows Terminal window
with a waited PowerShell parent, then closes only that test session. Uses local
console input records, never global keystrokes or a user's existing terminal.
"""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from terminal_smoke import ROOT, APP, OUT, K, U, COORD, RECT, CELL, Terminal, prepare
from terminal_display_smoke import PROMPT, until
from terminal_modern_smoke import command, resize, dimensions, capture_window

REPORT=ROOT/'out'/'terminal-modern'

def cell_lines(t):
    info=dimensions(t)
    height=min(info.size.Y,info.cursor.Y+2)
    cells=(CELL*(info.size.X*height))()
    rect=RECT(0,0,info.size.X-1,height-1)
    assert K.ReadConsoleOutputW(t.output,cells,COORD(info.size.X,height),COORD(0,0),C.byref(rect))
    rows=[]
    for y in range(height):
        row=[c for c in cells[y*info.size.X:(y+1)*info.size.X] if not c.attr&0x200]
        rows.append((''.join(c.char.wide or ' ' for c in row),[c.attr for c in row]))
    return rows

def check_color(t,text,expected):
    for line,attrs in cell_lines(t):
        if text in line and '>' not in line and '❯' not in line:
            at=line.index(text)
            found=[x&15 for x in attrs[at:at+len(text)]]
            if found==[expected]*len(text): return
    raise AssertionError(f'color {text!r} expected Win32 {expected}; '+repr(cell_lines(t)[-35:]))

def prepare_fixture():
    fixture=REPORT/'color-fixture'; fixture.mkdir(parents=True,exist_ok=True)
    for name in ('amber-module.dll','blue-code.cpp','green-image.png','purple-config.json','white-file.bin','中文日志.log'):
        (fixture/name).write_text('synthetic color fixture\n',encoding='utf-8')
    (fixture/'cyan-folder').mkdir(exist_ok=True)
    return fixture

def screen(t,name,commands):
    t.send('cls\r'); until(t,lambda s:PROMPT.search(s) and 'Rows ' not in s)
    for text,needle in commands:
        t.send(text+'\r'); until(t,lambda s:needle in s and PROMPT.search(s))
    return capture_window(t,name)

def native():
    prepare(); fixture=prepare_fixture(); results=[]; shots=[]
    t=Terminal('--skip-login')
    try:
        until(t,lambda s:PROMPT.search(s)); resize(t,120,34)
        original=W.DWORD(); K.GetConsoleMode(t.output,C.byref(original))
        # Force the real non-VT production writer, regardless of host default.
        assert K.SetConsoleMode(t.output,original.value & ~4)
        t.key(0x4c,'\x0c',8); until(t,lambda s:s.rstrip().endswith('+- >'))
        command(t,'use File'); command(t,'cd "'+str(fixture)+'"')
        for text,index in (('cyan-folder/',11),('amber-module.dll',14),('blue-code.cpp',9),
                           ('green-image.png',10),('purple-config.json',13),('white-file.bin',15)):
            check_color(t,text,index)
        results.append('non-VT Win32 exact directory/executable/code/image/config/body attributes')
        command(t,'show | grep "module"')
        check_color(t,'amber-',14); check_color(t,'module',14)
        # Distinguish search yellow from blue file base, then ensure restoration.
        command(t,'show | grep "code"'); check_color(t,'blue-',9); check_color(t,'code',14); check_color(t,'.cpp',9)
        results.append('pipeline keyword overlays file color and restores extension; row identity retained')
        command(t,'filter code'); check_color(t,'blue-',9); check_color(t,'code',14)
        command(t,'detail 1'); check_color(t,'blue-',9); check_color(t,'.cpp',9)
        command(t,'filter')
        shots.append(capture_window(t,'terminal-ansi16-120.png'))
        K.SetConsoleMode(t.output,original.value)
        for width in (120,80,40):
            resize(t,width,34)
            command(t,'show')
            shots.append(capture_window(t,f'terminal-color-{width}.png'))
        resize(t,120,34)
        for page in ('Settings','ServiceManager','Network'):
            command(t,'use '+page)
            shots.append(capture_window(t,f'terminal-color-{page.lower()}.png'))
        command(t,'use File'); command(t,'cd "'+str(fixture)+'"')
        screen(t,'terminal-color-search.png',[('show | grep -n "code"','matched /')])
        t.send('show | gr'); until(t,lambda s:'grep [Tab]' in s)
        shots.append(capture_window(t,'terminal-color-completion.png')); t.key(27)
        command(t,'nonexistent-color-test-command')
        shots.append(capture_window(t,'terminal-color-error.png'))
        results.append('real 40/80/120 native screenshots plus Settings/ServiceManager/Network/search/completion/error')
    finally: t.close()
    for variable in ('NO_COLOR','AEGISNT_NO_COLOR'):
        os.environ[variable]='1'; t=Terminal('--skip-login')
        try:
            until(t,lambda s:PROMPT.search(s)); resize(t,80,34)
            command(t,'use File'); command(t,'cd "'+str(fixture)+'"'); command(t,'show | find "code"')
            foregrounds={a&15 for text,attrs in cell_lines(t) for c,a in zip(text,attrs) if c.strip()}
            assert len(foregrounds)==1,foregrounds
            assert '\x1b' not in t.text()
            t.send('sh'); until(t,lambda s:'[Tab: show]' in s)
            shots.append(capture_window(t,f'terminal-{variable.lower()}.png')); t.key(27)
            results.append(variable+': uniform host foreground, no escapes, explicit Tab hint')
        finally: t.close(); os.environ.pop(variable,None)
    return results,shots

class ProcessHandle:
    def __init__(self,pid):
        K.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD]; K.OpenProcess.restype=W.HANDLE
        K.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)]
        K.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
        K.TerminateProcess.argtypes=[W.HANDLE,W.UINT]
        self.pid=pid; self.handle=K.OpenProcess(0x100001|0x1000,False,pid)
        assert self.handle,C.get_last_error()
    def poll(self):
        code=W.DWORD(); assert K.GetExitCodeProcess(self.handle,C.byref(code))
        return None if code.value==259 else code.value
    def wait(self,timeout):
        if K.WaitForSingleObject(self.handle,int(timeout*1000))!=0: raise subprocess.TimeoutExpired('test AegisNT',timeout)
        return self.poll()
    def terminate(self): K.TerminateProcess(self.handle,1)

def windows_terminal():
    prepare(); fixture=prepare_fixture()
    title='AegisNT RGB verification '+str(os.getpid())
    pidfile=REPORT/'wt-color-child.pid'; pidfile.unlink(missing_ok=True)
    script=REPORT/'wt-color-parent.ps1'
    quote=lambda value:"'"+str(value).replace("'","''")+"'"
    script.write_text("$ErrorActionPreference='Stop'\n"+
        "Remove-Item Env:NO_COLOR,Env:AEGISNT_NO_COLOR -ErrorAction SilentlyContinue\n"+
        "$child=Start-Process -FilePath "+quote(APP/'AegisNT.exe')+
        " -ArgumentList '--console','--reuse-console','--skip-login' -NoNewWindow -PassThru\n"+
        "[IO.File]::WriteAllText("+quote(pidfile)+",[string]$child.Id)\n$child.WaitForExit()\n",encoding='utf-8-sig')
    subprocess.run(['wt.exe','-w','new','--size','120,34','new-tab','--title',title,
                    '--suppressApplicationTitle','-d',str(APP),'powershell.exe','-NoLogo','-NoProfile',
                    '-ExecutionPolicy','Bypass','-File',str(script)],check=True,timeout=15)
    deadline=time.monotonic()+20
    while not pidfile.exists() and time.monotonic()<deadline: time.sleep(.1)
    assert pidfile.exists(),'Windows Terminal child did not start'
    t=Terminal.__new__(Terminal); t.process=ProcessHandle(int(pidfile.read_text())); t.input=t.output=None
    t.attach(t.process.pid)
    callback_type=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
    U.EnumWindows.argtypes=[callback_type,W.LPARAM]
    U.GetWindowTextW.argtypes=[W.HWND,W.LPWSTR,C.c_int]
    windows=[]
    @callback_type
    def collect(hwnd,_):
        value=C.create_unicode_buffer(512); U.GetWindowTextW(hwnd,value,512)
        if value.value==title: windows.append(hwnd)
        return True
    try:
        until(t,lambda s:PROMPT.search(s)); U.EnumWindows(collect,0)
        assert len(windows)==1,windows
        hwnd=windows[0]
        command(t,'use File'); command(t,'cd "'+str(fixture)+'"')
        shots=[capture_window(t,'terminal-wt-rgb-file.png',hwnd)]
        command(t,'show | grep -n "code"')
        t.send('show | gr'); until(t,lambda s:'grep [Tab]' in s)
        shots.append(capture_window(t,'terminal-wt-rgb-search.png',hwnd)); t.key(27)
        assert t.process.poll() is None
        return ['real Windows Terminal, waited PowerShell --reuse-console, RGB file/search/completion screenshots'],shots
    finally:
        t.close(); K.CloseHandle(t.process.handle)

def run():
    env={k:os.environ.get(k) for k in ('NO_COLOR','AEGISNT_NO_COLOR')}
    try:
        for k in env: os.environ.pop(k,None)
        results,shots=native()
        if '--windows-terminal' in sys.argv:
            extra,images=windows_terminal(); results+=extra; shots+=images
    finally:
        for k,v in env.items():
            if v is None: os.environ.pop(k,None)
            else: os.environ[k]=v
    (REPORT/'native-color-results.json').write_text(json.dumps({'passed':True,'results':results,'screenshots':shots},indent=2),encoding='utf-8')
    for result in results: print('PASS:',result)

if __name__=='__main__': run()
