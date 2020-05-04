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
        }
    ]
