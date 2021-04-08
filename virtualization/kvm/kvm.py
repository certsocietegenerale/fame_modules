from ..common import LibvirtVirtualization


class KVM(LibvirtVirtualization):

    name = "kvm"
    description = "Access KVM machines."

    config = [
        {
            'name': 'connection_string',
            'type': 'string',
            'description': 'KVM connection string for libvirtd. Usually of the form qemu[+ssh]:///[[user@]host]/system.',
            'default': 'qemu:///system'
        },
    ]
