import os

from kvm import KVM


class RemoteKVM(KVM):
    name = "remote_kvm"
    description = "Access remote KVM machines."

    config = [
        {
            'name': 'connection_string_remote',
            'type': 'string',
            'description': 'KVM connection string for remote libvirtd.',
            'default': 'qemu+ssh:///user@host/system'
        },
        {
            'name': 'ssh_private_key',
            'type': 'text',
            'description': 'The SSH private which is to be used by KVM.',
            'default': None
        },
        {
            'name': 'ssh_private_key_path',
            'type': 'string',
            'description': 'Path to SSH private key file.',
            'default': '/home/fame/.ssh/id_rsa'
        }
    ]

    def initialize(self, vm, base_url, snapshot):
        if self.ssh_private_key:
            try:
                # make sure SSH directory exists
                os.makedirs(os.path.dirname(self.ssh_private_key_path))
            except OSError:
                pass

            # write SSH private key to file
            with open(self.ssh_private_key_path, "w") as fp:
                fp.write(self.ssh_private_key)

            os.chmod(self.ssh_private_key_path, 0o600)

            try:
                # remove any existing public keys with the same name.
                # they are not necessary and can be generated from the
                # private key if needed
                os.unlink(self.ssh_private_key_path + ".pub")
            except OSError:
                pass

        super(KVM, self).initialize(vm, base_url, snapshot)

    def prepare(self):
        self.connection_string = self.connection_string_remote
        super(KVM, self).prepare()
