from .common import LibvirtVirtualization


class KVM(LibvirtVirtualization):

    name = "kvm"
    description = "Access KVM machines."

    config = [
        {
            'name': 'connection_string',
            'type': 'string',
            'description': 'KVM connection string for libvirtd. Usually of the form qemu[+ssh]:///[[user@]host]/system. Refer to the repository README for more detailed instructions / information.',
            'default': 'qemu:///system'
        },
        {
            'name': 'wait_for_vm_available',
            'type': 'bool',
            'description': 'Stall until the VM is not running before attempting to restore it.',
            'default': False
        }
    ]

    def prepare(self):
        super().prepare(self.wait_for_vm_available)
