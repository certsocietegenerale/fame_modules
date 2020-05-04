# fame_modules

Community modules for FAME.

This repository is automatically added to all FAME installations.

You can get more information (and screenshots !) about FAME on the [website](https://certsocietegenerale.github.io/fame) and in the [documentation](https://fame.readthedocs.io/).

## Remarks

The starting point for APKPlugins was the [maldrolyzer](https://github.com/maldroid/maldrolyzer) project, using an MIT license.

### KVM / libvirt modules

The connection string of libvirt for local VMs is default. If you want to use a remote VM host, the connection string usually is of the form `qemu+ssh:///user@host/system`. When using remote KVM hosts, make sure that SSH access to the remote machine is password-less (eg. by using private keys). If used, the SSH private key must be placed in the `$FAME_USER/.ssh/<filename>` folder so that SSH can find it.

It could also be handy to perform a ssh-keyscan of the KVM host prior to using the module. This ensures that no "The authenticity of host '[...]' can't be established." message is shown on the first connection (which would block the libvirt connection). The command should look like this: `ssh-keyscan <KVM host> >> $FAME_USER/.ssh/known_hosts`.
