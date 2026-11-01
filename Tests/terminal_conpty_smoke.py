"""Real Windows ConPTY transport; capture RGB bytes from the Release binary.

No terminal framework, simulated ANSI renderer, global keystrokes or account
credentials. An isolated fixture/config is shared with the other smoke suites;
run these suites sequentially.
"""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from terminal_smoke import ROOT, APP, K, COORD, prepare

REPORT = ROOT / "out" / "terminal-modern"

class STARTUPINFO(C.Structure):
    _fields_ = [("cb",W.DWORD),("reserved",W.LPWSTR),("desktop",W.LPWSTR),("title",W.LPWSTR),
                ("x",W.DWORD),("y",W.DWORD),("xsize",W.DWORD),("ysize",W.DWORD),
                ("xchars",W.DWORD),("ychars",W.DWORD),("fill",W.DWORD),("flags",W.DWORD),
                ("show",W.WORD),("reserved2",W.WORD),("bytes",W.LPBYTE),
                ("stdin",W.HANDLE),("stdout",W.HANDLE),("stderr",W.HANDLE)]
class STARTUPINFOEX(C.Structure):
    _fields_ = [("startup",STARTUPINFO),("attributes",W.LPVOID)]
class PROCESSINFO(C.Structure):
    _fields_ = [("process",W.HANDLE),("thread",W.HANDLE),("pid",W.DWORD),("tid",W.DWORD)]

K.CreatePipe.argtypes=[C.POINTER(W.HANDLE),C.POINTER(W.HANDLE),W.LPVOID,W.DWORD]
K.CreatePseudoConsole.argtypes=[COORD,W.HANDLE,W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)]
K.CreatePseudoConsole.restype=C.c_long
K.ResizePseudoConsole.argtypes=[W.HANDLE,COORD]
K.ClosePseudoConsole.argtypes=[W.HANDLE]
K.InitializeProcThreadAttributeList.argtypes=[W.LPVOID,W.DWORD,W.DWORD,C.POINTER(C.c_size_t)]
K.UpdateProcThreadAttribute.argtypes=[W.LPVOID,W.DWORD,C.c_size_t,W.LPVOID,C.c_size_t,W.LPVOID,W.LPVOID]
K.DeleteProcThreadAttributeList.argtypes=[W.LPVOID]
K.CreateProcessW.argtypes=[W.LPCWSTR,W.LPWSTR,W.LPVOID,W.LPVOID,W.BOOL,W.DWORD,W.LPVOID,W.LPCWSTR,C.POINTER(STARTUPINFOEX),C.POINTER(PROCESSINFO)]
K.ReadFile.argtypes=[W.HANDLE,W.LPVOID,W.DWORD,C.POINTER(W.DWORD),W.LPVOID]
K.WriteFile.argtypes=[W.HANDLE,W.LPCVOID,W.DWORD,C.POINTER(W.DWORD),W.LPVOID]
K.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
K.TerminateProcess.argtypes=[W.HANDLE,W.UINT]
K.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)]

class Pty:
    def __init__(self, columns=120):
        read_in, self.input, self.output, write_out = [W.HANDLE() for _ in range(4)]
        assert K.CreatePipe(C.byref(read_in),C.byref(self.input),None,0)
        assert K.CreatePipe(C.byref(self.output),C.byref(write_out),None,0)
        self.pty=W.HANDLE()
        hr=K.CreatePseudoConsole(COORD(columns,40),read_in,write_out,0,C.byref(self.pty))
        K.CloseHandle(read_in); K.CloseHandle(write_out)
        assert hr==0,hex(hr)
        size=C.c_size_t()
        K.InitializeProcThreadAttributeList(None,1,0,C.byref(size))
        attrs=C.create_string_buffer(size.value)
        assert K.InitializeProcThreadAttributeList(attrs,1,0,C.byref(size))
        assert K.UpdateProcThreadAttribute(attrs,0,0x00020016,self.pty,C.sizeof(W.HANDLE),None,None)
        si=STARTUPINFOEX(); si.startup.cb=C.sizeof(si); si.attributes=C.cast(attrs,W.LPVOID)
        self.pi=PROCESSINFO()
        cmd=C.create_unicode_buffer('cmd.exe /d /s /c ""'+str(APP/'AegisNT.exe')+'" --console --reuse-console --skip-login"')
        try:
            assert K.CreateProcessW(None,cmd,None,None,False,0x00080000,None,str(APP),C.byref(si),C.byref(self.pi)),C.get_last_error()
        finally:
            K.DeleteProcThreadAttributeList(attrs)
        K.CloseHandle(self.pi.thread)
        self.data=bytearray()
        def reader():
            buffer=C.create_string_buffer(65536); count=W.DWORD()
            while K.ReadFile(self.output,buffer,len(buffer),C.byref(count),None) and count.value:
                self.data.extend(buffer.raw[:count.value])
        self.reader=threading.Thread(target=reader,daemon=True); self.reader.start()
    def text(self): return bytes(self.data).decode('utf-8',errors='replace')
    def plain(self):
        text=re.sub(r'\x1b\][^\a]*(?:\a|\x1b\\)','',self.text())
        return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',text)
    def send(self,text):
        data=text.encode('utf-8'); count=W.DWORD()
        assert K.WriteFile(self.input,data,len(data),C.byref(count),None),C.get_last_error()
    def wait(self,needle,timeout=12,start=0):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if needle in self.plain()[start:]: return self.text()
            time.sleep(.04)
        raise AssertionError('ConPTY missing '+repr(needle)+'\n'+self.plain()[-5000:])
    def command(self,text):
        start=len(self.plain()); self.send(text+'\r')
        self.wait('❯',start=start); time.sleep(.08)
    def close(self):
        if K.WaitForSingleObject(self.pi.process,0)!=0:
            self.send('exit\r')
            if K.WaitForSingleObject(self.pi.process,6000)!=0: K.TerminateProcess(self.pi.process,1)
        K.CloseHandle(self.input)
        K.ClosePseudoConsole(self.pty)
        self.reader.join(timeout=4)
        K.CloseHandle(self.output); K.CloseHandle(self.pi.process)

def run():
    prepare()
    fixture=REPORT/'color-fixture'; fixture.mkdir(parents=True,exist_ok=True)
    (fixture/'blue-code.cpp').write_text('// fixture',encoding='utf-8')
    (fixture/'purple-config.json').write_text('{}',encoding='utf-8')
    (fixture/'green-image.png').write_bytes(b'color test fixture, not an image')
    (fixture/'amber-module.dll').write_bytes(b'color test fixture, not executable')
    (fixture/'cyan-folder').mkdir(exist_ok=True)
    results=[]
    env={k:os.environ.get(k) for k in ('NO_COLOR','AEGISNT_NO_COLOR','WT_SESSION','COLORTERM','ConEmuANSI')}
    try:
        for k in env: os.environ.pop(k,None)
        t=Pty()
        try:
            raw=t.wait('❯')
            assert re.search(r'\x1b\[[0-9;]*38;2;92;226;255m',raw),raw[-3000:]
            results.append('real ConPTY automatically emits 24-bit RGB without WT_SESSION or COLORTERM')
            t.command('use File'); t.command('cd "'+str(fixture)+'"')
            t.command('show | grep -n "module"')
            raw=t.text()
            for rgb in ('142;193;255','215;151;255','93;225;179','255;177;92','105;220;255','255;224;102'):
                assert '38;2;'+rgb+'m' in raw,rgb
            assert 'snapshot row numbers; detail <n>' in t.plain()
            results.append('RGB file types, directory, row-numbered pipeline search and restored base color')
            t.send('show | gr'); t.wait('grep [Tab]'); t.send('\x1b')
            for columns in (40,80,120):
                assert K.ResizePseudoConsole(t.pty,COORD(columns,40))==0
                t.send('\x0c'); time.sleep(.15)
                t.command('show')
            for page in ('Settings','ServiceManager','Network'):
                t.command('use '+page)
                assert page in t.plain()
            results.append('40/80/120 resize, completion hint, File/Settings/ServiceManager/Network under ConPTY')
            (REPORT/'conpty-rgb-output.ansi').write_bytes(bytes(t.data))
            (REPORT/'conpty-rgb-output.txt').write_text(t.plain(),encoding='utf-8')
        finally: t.close()
        for variable in ('NO_COLOR','AEGISNT_NO_COLOR'):
            os.environ[variable]='1'; t=Pty(80)
            try:
                t.wait('❯'); t.command('use File'); t.command('show | find "dll"')
                raw=t.text()
                # Transport still sends cursor/erase sequences. Color SGR must
                # be absent; these are different from console positioning.
                sgr=re.findall(r'\x1b\[([0-9;]*)m',raw)
                assert all(x in ('','0') for x in sgr),sgr
                (REPORT/('conpty-'+variable.lower()+'.ansi')).write_bytes(bytes(t.data))
                results.append(variable+': real ConPTY has no color SGR')
            finally: t.close(); os.environ.pop(variable,None)
    finally:
        for k,v in env.items():
            if v is None: os.environ.pop(k,None)
            else: os.environ[k]=v
    (REPORT/'conpty-color-results.json').write_text(json.dumps({'passed':True,'results':results},indent=2),encoding='utf-8')
    for result in results: print('PASS:',result)

if __name__=='__main__': run()
