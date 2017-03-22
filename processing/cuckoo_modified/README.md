This module submits the file to Cuckoo Sandbox and retrieves results (report and memory dump).

It is only compatible with the [cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) fork.

# Mandatory configuration

This module provides an "Allow Internet Connection" option that **will not work** without appropriate configuration.

For this option to work, you should make sure that several virtual machines are configured in your Cuckoo sandbox instance. The virtual machines that have access to the Internet should be tagged (in cuckoo's configuration) **internet_access**. The VMs without internet access should be tagged **no_internet**.
