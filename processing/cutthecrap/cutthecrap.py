import threading
from time import sleep
from array import array
from shutil import move

from fame.core.module import IsolatedProcessingModule
from fame.common.exceptions import ModuleInitializationError


try:
    import win32api
    import win32gui
    import win32con
    import win32process

    HAVE_PYWIN32 = True
except ImportError:
    HAVE_PYWIN32 = False


try:
    import frida

    HAVE_FRIDA = True
except ImportError:
    HAVE_FRIDA = False


class ClickThread(threading.Thread):
    def __init__(self):
        super(ClickThread, self).__init__()
        self._windows = {}
        self._should_stop = threading.Event()
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
        self._should_stop.set()

    def should_run(self):
        return not self._should_stop.isSet()

    def foreach_child(self):
        def callback(hwnd, window_hwnd):
            classname = win32gui.GetClassName(hwnd).lower()

            buffer_len = win32gui.SendMessage(hwnd, win32con.WM_GETTEXTLENGTH, 0, 0) + 1
            text = array('b', b'\x00\x00' * buffer_len)
            win32gui.SendMessage(hwnd, win32con.WM_GETTEXT, buffer_len, text)
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
                    except Exception:
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
            self._should_stop.wait(0.5)


FRIDA_SCRIPT = """
Module.load("wininet.dll");
var moduleMap = new ModuleMap();

Interceptor.attach(Module.getExportByName("kernel32.dll", "CreateFileA"), {
  onEnter: function (args) {
    var desiredAccess = args[1].toInt32();

    if (desiredAccess & 0x40000000) {
      send({
        api: "CreateFileA",
        filename: args[0].readCString(),
        desired_access: desiredAccess,
        stack_trace: [
          ...new Set(
            Thread.backtrace(this.context, Backtracer.ACCURATE).map(
              (address) => moduleMap.find(address)?.name
            )
          ),
        ],
      });
    }
  },
});

Interceptor.attach(Module.getExportByName("kernel32.dll", "CreateFileW"), {
  onEnter: function (args) {
    var desiredAccess = args[1].toInt32();

    if (desiredAccess & 0x40000000) {
      send({
        api: "CreateFileW",
        filename: args[0].readUtf16String(),
        desired_access: desiredAccess,
        stack_trace: [
          ...new Set(
            Thread.backtrace(this.context, Backtracer.ACCURATE).map(
              (address) => moduleMap.find(address)?.name
            )
          ),
        ],
      });
    }
  },
});

Interceptor.replace(
  Module.getExportByName("kernel32.dll", "WinExec"),
  new NativeCallback(
    (lpCmdLine, uCmdShow) => {
      send({
        api: "WinExec",
        command_line: lpCmdLine.readCString(),
      });

      return 0x21;
    },
    "uint",
    ["pointer", "uint"],
    "stdcall"
  )
);

Interceptor.replace(
  Module.getExportByName("kernel32.dll", "CreateProcessA"),
  new NativeCallback(
    (
      lpApplicationName,
      lpCommandLine,
      lpProcessAttributes,
      lpThreadAttributes,
      bInheritHandles,
      dwCreationFlags,
      lpEnvironment,
      lpCurrentDirectory,
      lpStartupInfo,
      lpProcessInformation
    ) => {
      send({
        api: "CreateProcessA",
        application: lpApplicationName.readCString(),
        command_line: lpCommandLine.readCString(),
      });

      return 1;
    },
    "bool",
    [
      "pointer",
      "pointer",
      "pointer",
      "pointer",
      "bool",
      "uint",
      "pointer",
      "pointer",
      "pointer",
      "pointer",
    ],
    "stdcall"
  )
);

Interceptor.replace(
  Module.getExportByName("kernel32.dll", "CreateProcessW"),
  new NativeCallback(
    (
      lpApplicationName,
      lpCommandLine,
      lpProcessAttributes,
      lpThreadAttributes,
      bInheritHandles,
      dwCreationFlags,
      lpEnvironment,
      lpCurrentDirectory,
      lpStartupInfo,
      lpProcessInformation
    ) => {
      send({
        api: "CreateProcessA",
        application: lpApplicationName.readUtf16String(),
        command_line: lpCommandLine.readUtf16String(),
      });

      return 1;
    },
    "bool",
    [
      "pointer",
      "pointer",
      "pointer",
      "pointer",
      "bool",
      "uint",
      "pointer",
      "pointer",
      "pointer",
      "pointer",
    ],
    "stdcall"
  )
);

Interceptor.attach(Module.getExportByName("wininet.dll", "InternetCrackUrlA"), {
  onEnter: function (args) {
    send({
      api: "InternetCrackUrlA",
      url: args[0].readCString(),
      stack_trace: [
        ...new Set(
          Thread.backtrace(this.context, Backtracer.ACCURATE).map(
            (address) => moduleMap.find(address)?.name
          )
        ),
      ],
    });
  },
});

Interceptor.attach(Module.getExportByName("wininet.dll", "InternetCrackUrlW"), {
  onEnter: function (args) {
    send({
      api: "InternetCrackUrlW",
      url: args[0].readUtf16String(),
      stack_trace: [
        ...new Set(
          Thread.backtrace(this.context, Backtracer.ACCURATE).map(
            (address) => moduleMap.find(address)?.name
          )
        ),
      ],
    });
  },
});

Interceptor.attach(
  Module.getExportByName("ole32.dll", "ObjectStublessClient20"),
  {
    onEnter: function (args) {
      send({
        api: "ObjectStublessClient20",
        language: args[1].readUtf16String(),
        query: args[2].readUtf16String(),
        stack_trace: [
          ...new Set(
            Thread.backtrace(this.context, Backtracer.ACCURATE).map(
              (address) => moduleMap.find(address)?.name
            )
          ),
        ],
      });
    },
  }
);

Interceptor.replace(
  Module.getExportByName("ole32.dll", "ObjectStublessClient24"),
  new NativeCallback(
    (ignored, lpObject, lpMethod) => {
      send({
        api: "ObjectStublessClient24",
        object: lpObject.readUtf16String(),
        method: lpMethod.readUtf16String(),
      });

      return 1;
    },
    "uint",
    ["pointer", "pointer", "pointer"],
    "stdcall"
  )
);
"""


class CutTheCrap(IsolatedProcessingModule):
    name = "cutthecrap"
    description = "Dropper analysis using Frida."
    acts_on = ["word", "html", "powerpoint", "excel", "javascript", "rtf", "vbscript"]

    config = [
        {
            "name": "office_path",
            "type": "str",
            "default": "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\",
            "description": "Path of the Microsoft Office installation to use.",
        },
        {
            "name": "add_to_support_files",
            "type": "bool",
            "default": False,
            "description": "Adds the dropped files to support files (so that they can be downloaded).",
        },
        {
            "name": "add_to_extracted_files",
            "type": "bool",
            "default": True,
            "description": "Adds the dropped files to extracted files (they will have their own analysis).",
        },
        {
            "name": "stop_on_process_creation",
            "type": "bool",
            "default": True,
            "description": "Stop the analysis when a process creation attempt was detected."
        },
        {
            "name": "timeout",
            "type": "integer",
            "default": 30,
            "description": "Maximum duration of an analysis"
        }
    ]

    def initialize(self):
        # Check dependencies
        if not HAVE_FRIDA:
            raise ModuleInitializationError(self, "Missing dependency: frida")
        if not HAVE_PYWIN32:
            raise ModuleInitializationError(self, "Missing dependency: pywin32")

    def set_extension(self, target, file_type):
        extensions = {"javascript": "js", "vbscript": "vbs"}

        if file_type in extensions:
            dst = "{}.{}".format(target, extensions[file_type])
            move(target, dst)
            target = dst

        return target

    def callback(self, message, data):
        handlers = {
            "CreateFileA": self.create_file_callback,
            "CreateFileW": self.create_file_callback,
            "CreateProcessA": self.create_process_callback,
            "CreateProcessW": self.create_process_callback,
            "WinExec": self.create_process_callback,
            "InternetCrackUrlA": self.url_callback,
            "InternetCrackUrlW": self.url_callback,
            "ObjectStublessClient20": self.wmi_callback,
            "ObjectStublessClient24": self.wmi_object_callback
        }

        if "payload" in message and message["payload"]["api"] in handlers:
            if "stack_trace" in message["payload"]:
                for dll_name in message["payload"]["stack_trace"]:
                    if dll_name in ["scrrun.dll", "msado15.dll", "VBE7.DLL", "urlmon.dll", "OLEAUT32.dll"]:
                        break
                else:
                    self.log("debug", "ignoring message because of stack: {}".format(message))
                    return

            handlers[message["payload"]["api"]](message["payload"])
        else:
            self.log("debug", str(message))

    def create_file_callback(self, args):
        desired_access = args["desired_access"]

        # Make sure we have a signed integer
        if desired_access < 0:
            desired_access += 2**32

        # Only interested in written files from macros
        if desired_access & 0x40000000:
            self.record_file(args["filename"], args["api"])

    def create_process_callback(self, args):
        if args.get("command_line"):
            self.record_exec(args["command_line"], args["api"])
        else:
            self.record_exec(args["application"], args["api"])

        self.process_created.set()

    def url_callback(self, args):
        self.record_http(args["url"], "InternetCrackUrl")
        self.add_ioc(args["url"], ["payload_delivery"])

    def wmi_callback(self, args):
        self.record_wmi(args["query"], "ObjectStublessClient20")

    def wmi_object_callback(self, args):
        self.record_wmi_object(args["object"], args["method"], "ObjectStublessClient24")

        if args["object"].lower() == "win32_process" and args["method"].lower() == "create":
            self.process_created.set()

    def each_with_type(self, target, file_type):
        self.process_created = threading.Event()

        self.paths = {
            "word": "{}\\{}".format(self.office_path, "WINWORD.EXE"),
            "rtf": "{}\\{}".format(self.office_path, "WINWORD.EXE"),
            "html": "{}\\{}".format(self.office_path, "WINWORD.EXE"),
            "excel": "{}\\{}".format(self.office_path, "EXCEL.EXE"),
            "powerpoint": "{}\\{}".format(self.office_path, "POWERPOINT.EXE"),
            "javascript": "C:\\Windows\\system32\\wscript.exe",
            "vbscript": "C:\\Windows\\system32\\wscript.exe",
        }

        self.files = set()
        self.results = {"actions": []}

        monkey = ClickThread()
        monkey.click_on(
            "Microsoft Excel",
            "Yes",
            "is in a different format than specified by the file extension",
        )
        monkey.click_on(
            "Microsoft Word", "OK", "command cannot be performed because a dialog box is open"
        )
        monkey.click_on("Microsoft Word", "No", "start Word in safe mode")
        monkey.click_on("Microsoft Word", "Yes", "caused a serious error")
        monkey.click_on("File In Use", "OK", "locked for editing")
        monkey.click_on("Microsoft Word", "Yes", "that may refer to other files")
        monkey.click_on("Microsoft Excel", "Yes", "that may refer to other files")
        monkey.click_on("Microsoft Word", "Yes", "Do you want to start")
        monkey.click_on("Microsoft Excel", "Yes", "Do you want to start")
        monkey.close("Activation Wizard")
        monkey.start()

        try:
            target = self.set_extension(target, file_type)
            executable = self.paths[file_type]
            cmdline = f"\"{executable}\" \"{target}\""

            # Start the process in a paused state
            process = win32process.CreateProcess(
                executable,
                cmdline,
                None,
                None,
                False,
                win32process.CREATE_SUSPENDED,
                None,
                None,
                win32process.STARTUPINFO(),
            )

            # Add hooks with Frida to trace interesting API calls
            session = frida.attach(process[2])
            script = session.create_script(FRIDA_SCRIPT)
            script.on('message', self.callback)
            script.load()

            # Resume the process so that it executes
            win32process.ResumeThread(process[1])

            # Let the process execute for a while
            if self.stop_on_process_creation:
                self.process_created.wait(self.timeout)
            else:
                sleep(self.timeout)

            # Stop Frida session and kill process
            session.detach()
            win32api.TerminateProcess(process[0], -1)
        finally:
            monkey.stop()
            monkey.join()

        for i, dropped_file in enumerate(self.files):
            if self.add_to_support_files:
                basename = dropped_file.split("\\")[-1].split("/")[-1]
                self.add_support_file("{}_{}".format(i, basename), dropped_file)
            if self.add_to_extracted_files:
                self.add_extracted_file(dropped_file)
        del self.files

        # Restore the VM if we did not catch a process creation
        if not self.process_created.is_set():
            self.should_restore = True

        return len(self.results["actions"]) > 0

    def record(self, action, params, comment):
        self.results["actions"].append((action, params, comment))

    def record_http(self, params, comment):
        self.record("HTTP Request", params, comment)

    def record_exploit(self, cve):
        self.record("Triggered Exploit", "", cve)

    def record_exec(self, params, comment):
        self.record("Executed Command", params, comment)

    def record_file(self, params, comment):
        self.files.add(params)
        self.record("Modified File", params, comment)

    def record_wmi(self, params, comment):
        self.record("WMI Query", params, comment)

    def record_wmi_object(self, obj, method, comment):
        self.record("WMI Call", "{}->{}".format(obj, method), comment)
