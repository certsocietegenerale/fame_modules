### Installation

This module requires `libvirt` to work properly. It can be installed with `sudo apt install libvirt-dev`.

### KVM Configuration

The connection string of libvirt for local VMs is default. If you want to use a remote VM host, the connection string usually is of the form `qemu+ssh:///user@host/system`. When using remote KVM hosts, make sure that SSH access to the remote machine is password-less (eg. by using private keys). If used, the SSH private key must be placed in the `$FAME_USER/.ssh/<filename>` folder so that SSH can find it.

It could also be handy to perform a ssh-keyscan of the KVM host prior to using the module. This ensures that no "The authenticity of host '[...]' can't be established." message is shown on the first connection (which would block the libvirt connection). The command should look like this: `ssh-keyscan <KVM host> >> $FAME_USER/.ssh/known_hosts`.
