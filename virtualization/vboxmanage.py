from datetime import timedelta
from subprocess import Popen, PIPE
from distutils.spawn import find_executable

from fame.common.utils import iterify, with_timeout
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import VirtualizationModule


class VBoxManage(VirtualizationModule):
    name = "virtualbox"
    description = "Access Virtualbox machines."

    def initialize(self, vm, base_url, snapshot=None):
        VirtualizationModule.initialize(self, vm, base_url, snapshot)

        if find_executable('VBoxManage') is None:
            raise ModuleInitializationError(self, "Missing dependency: VBoxManage")

        return True

    def is_running(self):
        return self._state() == "running"

    def restore_snapshot(self):
        if self.snapshot is None:
            self._vbox("snapshot", self.vm_label, "restorecurrent")
        else:
            self._vbox("snapshot", self.vm_label, "restore", self.snapshot)

        self._wait_for_completion("saved")

    def start(self):
        self._vbox("startvm", self.vm_label, "--type", "gui")

        self._wait_for_completion("running")

    def stop(self):
        self._vbox("controlvm", self.vm_label, "poweroff")
        self._wait_for_completion("poweroff")

        # For some reason, the restore fails in some cases if we do not wait
        # a little, so we are waiting for 'SessionName' to disapear from the
        # vminfo.
        def session_ended():
            return 'SessionName="' not in self._vbox("showvminfo", self.vm_label, "--machinereadable")

        if with_timeout(session_ended, timedelta(seconds=30), 0.5) is None:
            raise ModuleExecutionError('Timeout while waiting for machine "{}" to poweroff properly.'.format(self.vm_label))

    def _wait_for_completion(self, state):
        state = iterify(state)

        def correct_state():
            return self._state() in state

        if with_timeout(correct_state, timedelta(seconds=120), 0.5) is None:
            raise ModuleExecutionError('Timeout while waiting for machine "{}" to be "{}"'.format(self.vm_label, self.state))

    def _state(self, to_print=False):
        output = self._vbox("showvminfo", self.vm_label, "--machinereadable")
        if to_print:
            print(output)

        for line in output.splitlines():
            if line.startswith('VMState="'):
                return line[9:-1]

        raise ModuleExecutionError('Could not determine machine state for "{}"'.format(self.vm_label))

    def _vbox(self, *args):
        p = Popen(["VBoxManage"] + list(args), stdout=PIPE, stderr=PIPE, close_fds=True)
        output, error = p.communicate()

        return output
