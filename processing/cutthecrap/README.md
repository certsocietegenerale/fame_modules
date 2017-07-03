This module analyzes malware droppers in Office documents, VB scripts or Javascript files. It is using WinAppDbg with some hooks to extract useful information such as accessed URLs and created processes.

It was based on https://github.com/tehsyntx/loffice.

## Installation

This is an `IsolatedProcessingModule` which needs a properly configured virtual machine in order to execute properly.

In order to create this virtual machine, you have to follow the process described at https://fame.readthedocs.io/en/latest/installation.html#isolated-processing-modules, with the following additional requirements:

* Install a Windows operating system.
* Install the Office suite. The best results will be with Microsoft Office 2010 in english. Make sure to disable security and enable macros by default.
* Install dependencies:

    > pip install winappdbg pypiwin32

Note that you should use Python 32bits on this VM for cutthecrap to work as intended.
