from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import VirtualizationModule


try:
    import libvirt

    HAVE_LIBVIRT = True
except ImportError:
    HAVE_LIBVIRT = False


class LibvirtVirtualization(VirtualizationModule):
    def initialize(self, vm, base_url, snapshot=None):
        VirtualizationModule.initialize(self, vm, base_url, snapshot)

        if not HAVE_LIBVIRT:
            raise ModuleInitializationError(self, "Missing dependency: libvirt")

        return True

    def prepare(self):
        self.con = libvirt.open(self.connection_string)

        try:
            self.vm = self.con.lookupByName(self.vm_label)
            VirtualizationModule.prepare(self)
        finally:
            self.con.close()

    def is_running(self):
        return self._state() == 1

    def restore_snapshot(self):
        snapshot = None

        if self.snapshot is None:
            if self.vm.hasCurrentSnapshot():
                snapshot = self.vm.snapshotCurrent()
            else:
                raise ModuleExecutionError('Machine "{}" does not have a current snapshot. Please specify a snapshot name in the configuration.'.format(self.vm_label))
        else:
            snapshot = self.vm.snapshotLookupByName(self.snapshot)

        self.vm.revertToSnapshot(snapshot)

    def start(self):
        if not self.is_running():
            self.vm.create()

    def stop(self):
        self.vm.destroy()

    def _state(self):
        return self.vm.state()[0]
