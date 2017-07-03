from .common import LibvirtVirtualization


class KVM(LibvirtVirtualization):

    name = "kvm"
    description = "Access KVM machines."
    connection_string = 'qemu:///system'
