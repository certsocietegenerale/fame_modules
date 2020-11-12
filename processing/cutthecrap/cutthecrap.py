

import threading
from time import time
from array import array
from shutil import move
from multiprocessing import Process

from fame.core.module import IsolatedProcessingModule
from fame.common.exceptions import ModuleInitializationError


try:
    from winappdbg import Debug, EventHandler, Process, win32
    HAVE_WINAPPDBG = True
except:
    HAVE_WINAPPDBG = False

    class EventHandler:
        pass


try:
    import win32gui
    import win32con

    HAVE_PYWIN32 = True
except ImportError:
    HAVE_PYWIN32 = False


class ClickThread(threading.Thread):
    def __init__(self):
        super(ClickThread, self).__init__()
        self._windows = {}
        self._stop = threading.Event()
        self.clicks = {}
        self.to_close = set()

    def click_on(self, window, button, text=""):
        window = window.lower()
        button = button.lower()
        text = text.lower()

        if window not in self.clicks:
            self.clicks[window] = []

        self.clicks[window].append({
            "text": text,
            "button": button
        })

    def close(self, window):
        self.to_close.add(window.lower())

    def stop(self):
        self._stop.set()

    def should_run(self):
        return not self._stop.isSet()

    def foreach_child(self):
        def callback(hwnd, window_hwnd):
            classname = win32gui.GetClassName(hwnd).lower()

            buffer_len = win32gui.SendMessage(hwnd, win32con.WM_GETTEXTLENGTH, 0, 0) + 1
            text = array('b', b'\x00\x00' * buffer_len)
            text_len = win32gui.SendMessage(hwnd, win32con.WM_GETTEXT, buffer_len, text)
            text = win32gui.PyGetString(text.buffer_info()[0], buffer_len - 1).lower()

            for match in self._windows[window_hwnd]['matches']:
                if match["text"] in text:
                    self._windows[window_hwnd]['to_click'].append(match["button"])

            if "button" in classname:
                self._windows[window_hwnd]['buttons'].append({
                    'text': text,
                    'handle': hwnd,
                })

            return True

        return callback

    def foreach_window(self):
        def callback(hwnd, lparam):
            title = win32gui.GetWindowText(hwnd).lower()

            for window in self.to_close:
                if window in title:
                    win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                    print("Closed window ({})".format(title))

            for window in self.clicks:
                if window in title:
                    self._windows[hwnd] = {
                        "matches": self.clicks[window],
                        "to_click": [],
                        "buttons": []
                    }
                    try:
                        win32gui.EnumChildWindows(hwnd, self.foreach_child(), hwnd)
                    except:
                        print("EnumChildWindows failed, moving on.")

                    for button_toclick in self._windows[hwnd]['to_click']:
                        for button in self._windows[hwnd]['buttons']:
                            if button_toclick in button['text']:
                                win32gui.SetForegroundWindow(button['handle'])
                                win32gui.SendMessage(button['handle'], win32con.BM_CLICK, 0, 0)
                                print("Clicked on button ({} / {})".format(title, button['text']))

                    del self._windows[hwnd]

            return True

        return callback

    def run(self):
        while self.should_run():
            win32gui.EnumWindows(self.foreach_window(), 0)
            self._stop.wait(0.5)


class CutTheCrap(IsolatedProcessingModule, EventHandler):
    name = "cutthecrap"
    description = "Dropper analysis using WinDbg."
    acts_on = ["word", "html", "powerpoint", "excel", "javascript", "rtf", "vbscript"]

    config = [
        {
            'name': 'office_path',
            'type': 'str',
            'default': 'C:\\Program Files (x86)\\Microsoft Office\\Office14\\',
            'description': 'Path of the Microsoft Office installation to use.'
        },
        {
            'name': 'mscomctl_cve_2012_0158_addr',
            'type': 'integer',
            'default': 0x275D6BD6,
            'description': 'Address of the function vulnerable to CVE-2012-0158.'
        },
        {
            'name': 'add_to_support_files',
            'type': 'bool',
            'default': False,
            'description': 'Adds the dropped files to support files (so that they can be downloaded).',
        },
        {
            'name': 'add_to_extracted_files',
            'type': 'bool',
            'default': True,
            'description': 'Adds the dropped files to extracted files (they will have their own analysis).',
        }
    ]

    def initialize(self):
        # Check dependencies
        if not HAVE_WINAPPDBG:
            raise ModuleInitializationError(self, "Missing dependency: WinAppDbg")
        if not HAVE_PYWIN32:
            raise ModuleInitializationError(self, "Missing dependency: pywin32")

        self.timeout = 30

    def set_extension(self, target, file_type):
        extensions = {
            'javascript': 'js',
            'vbscript': 'vbs'
        }

        if file_type in extensions:
            dst = "{}.{}".format(target, extensions[file_type])
            move(target, dst)
            target = dst

        return target

    def each_with_type(self, target, file_type):
        self.paths = {
            'word': "{}\\{}".format(self.office_path, "WINWORD.EXE"),
            'rtf': "{}\\{}".format(self.office_path, "WINWORD.EXE"),
            'html': "{}\\{}".format(self.office_path, "WINWORD.EXE"),
            'excel': "{}\\{}".format(self.office_path, "EXCEL.EXE"),
            'powerpoint': "{}\\{}".format(self.office_path, "POWERPOINT.EXE"),
            'javascript': 'C:\\Windows\\system32\\wscript.exe',
            'vbscript': 'C:\\Windows\\system32\\wscript.exe'
        }

        self.files = set()
        self.results = {
            "actions": []
        }

        monkey = ClickThread()
        monkey.click_on("Microsoft Excel", "Yes", "is in a different format than specified by the file extension")
        monkey.click_on("Microsoft Word", "OK", "command cannot be performed because a dialog box is open")
        monkey.click_on("Microsoft Word", "No", "start Word in safe mode")
        monkey.click_on("Microsoft Word", "Yes", "caused a serious error")
        monkey.click_on("File In Use", "OK", "locked for editing")
        monkey.click_on("Microsoft Word", "Yes", "that may refer to other files")
        monkey.click_on("Microsoft Excel", "Yes", "that may refer to other files")
        monkey.click_on("Microsoft Word", "Yes", "Do you want to start")
        monkey.click_on("Microsoft Excel", "Yes", "Do you want to start")
        monkey.close("Activation Wizard")
        monkey.start()

        target = self.set_extension(target, file_type)
        args = [self.paths[file_type], target]

        pids = []
        maxtime = time() + self.timeout

        with Debug(self, bKillOnExit=False) as debug:
            debug.execv(args)

            pids = debug.get_debugee_pids()

            while debug and time() < maxtime:
                try:
                    debug.wait(1000)
                except WindowsError as e:
                    if e.winerror in (win32.ERROR_SEM_TIMEOUT,
                                      win32.WAIT_TIMEOUT):
                        continue
                    raise

                try:
                    debug.dispatch()
                finally:
                    debug.cont()

        for pid in pids:
            try:
                Process(pid).kill()
            except:
                pass

        monkey.stop()
        monkey.join()

        for i, dropped_file in enumerate(self.files):
            if self.add_to_support_files:
                basename = dropped_file.split('\\')[-1].split('/')[-1]
                self.add_support_file("{}_{}".format(i, basename), dropped_file)
            if self.add_to_extracted_files:
                self.add_extracted_file(dropped_file)
        del self.files

        # Restore the VM if we did not catch a process creation
        if len(self.results['actions']) == 0:
            self.should_restore = True

        return len(self.results['actions']) > 0

    def load_dll(self, event):

        module = event.get_module()
        pid = event.get_pid()

        if module.match_name("kernel32.dll"):
            address = module.resolve("CreateProcessA")
            event.debug.break_at(pid, address, self.bp_CreateProcessA)
            address = module.resolve("CreateProcessW")
            event.debug.break_at(pid, address, self.bp_CreateProcessW)

            address = module.resolve("WinExec")
            event.debug.break_at(pid, address, self.bp_WinExec)

            address = module.resolve("CreateFileA")
            event.debug.break_at(pid, address, self.bp_CreateFileA)
            address = module.resolve("CreateFileW")
            event.debug.break_at(pid, address, self.bp_CreateFileW)

        if module.match_name("mscomctl.ocx"):
            address = self.mscomctl_cve_2012_0158_addr
            event.debug.break_at(pid, address, self.sig_cve_2012_0158)

        if module.match_name("wininet.dll"):
            address = module.resolve("InternetCrackUrlA")
            event.debug.break_at(pid, address, self.bp_InternetCrackUrlA)
            address = module.resolve("InternetCrackUrlW")
            event.debug.break_at(pid, address, self.bp_InternetCrackUrlW)

        if module.match_name("winhttp.dll"):
            address = module.resolve("WinHttpCrackUrl")
            event.debug.break_at(pid, address, self.bp_WinHttpCrackUrl)

    def sig_cve_2012_0158(self, event):
        thread = event.get_thread()
        _, _, _, size = thread.read_stack_dwords(4)

        if size > 12:
            self.record_exploit('CVE-2012-0158')

    def bp_WinExec(self, event):
        proc = event.get_process()
        thread = event.get_thread()

        lpCmdLine = thread.read_stack_dwords(2)[1]
        cmdline = proc.peek_string(lpCmdLine)

        self.record_exec(cmdline, 'WinExec')

        Process(event.get_pid()).kill()

    def bp_CreateProcess(self, event, fUnicode=True):
        proc = event.get_process()
        thread = event.get_thread()

        lpApplicationName, lpCommandLine = thread.read_stack_dwords(3)[1:]
        application = proc.peek_string(lpApplicationName, fUnicode=fUnicode)
        cmdline = proc.peek_string(lpCommandLine, fUnicode=fUnicode)

        if "splwow64" not in application:
            if cmdline != "":
                self.record_exec(cmdline, 'CreateProcess')
            else:
                self.record_exec(application, 'CreateProcess')

            Process(event.get_pid()).kill()

    def bp_CreateProcessW(self, event):
        return self.bp_CreateProcess(event)

    def bp_CreateProcessA(self, event):
        return self.bp_CreateProcess(event, False)

    def bp_CreateFile(self, event, fUnicode=True):
        proc = event.get_process()
        thread = event.get_thread()
        lpFileName, dwDesiredAccess = thread.read_stack_dwords(3)[1:]

        filename = proc.peek_string(lpFileName, fUnicode=fUnicode)

        if dwDesiredAccess & 0x40000000:
            stack_trace = thread.get_stack_trace()
            for fcall in stack_trace:
                if fcall[2].split('\\')[-1] in ['scrrun.dll', 'msado15.dll', 'VBE7.DLL']:
                    self.record_file(filename, 'CreateFile')
                    break
            else:
                self.log('debug', 'ignoring file {}'.format(filename))
                self.log('debug', stack_trace)

    def bp_CreateFileW(self, event):
        return self.bp_CreateFile(event)

    def bp_CreateFileA(self, event):
        return self.bp_CreateFile(event, False)

    def bp_InternetCrackUrl(self, event, fUnicode=True):
        proc = event.get_process()
        thread = event.get_thread()
        lpszUrl = thread.read_stack_dwords(2)[1]

        url = proc.peek_string(lpszUrl, fUnicode=fUnicode)
        self.record_http(url, 'InternetCrackUrl')
        self.add_ioc(url, ['payload_delivery'])

    def bp_InternetCrackUrlW(self, event):
        return self.bp_InternetCrackUrl(event)

    def bp_InternetCrackUrlA(self, event):
        return self.bp_InternetCrackUrl(event, False)

    def bp_WinHttpCrackUrl(self, event):
        return self.bp_InternetCrackUrl(event)

    def record(self, action, params, comment):
        self.results['actions'].append((action, params, comment))

    def record_http(self, params, comment):
        self.record('HTTP Request', params, comment)

    def record_exploit(self, cve):
        self.record('Triggered Exploit', '', cve)

    def record_exec(self, params, comment):
        self.record('Executed Command', params, comment)

    def record_file(self, params, comment):
        self.files.add(params)
        self.record('Modified File', params, comment)
