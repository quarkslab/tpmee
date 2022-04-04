

# README

## GENERAL INFO

Project: TPMEavesEmu (TPMEE)  
Contributors: Benoît Forgette ([@Mad5quirrel](https://twitter.com/Mad5quirrel))  
License: [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.txt)  
Date: 04-03-22


## GOAL

TPMEavesEmu will help to exploit weak implementation of library or program that
used TPM.
This tool allow to:
- identify the wrong configuration of the PCR
- extract secrets release with TPM_CC_UNSEAL
- get a privilege access on Linux Operating System due to a weak implementation
of automatic decrytion program.


## How it works

Our approach emulates the targeted computer by connecting all the
components it needs to run as usual. This emulation makes it possible
to listen to the communication between the computer and the TPM. To
go further, it is possible to modify the communication flow between the
computer and the TPM in order to compromise the computer. For example,
the generation of a random number by the TPM can be rigged. In the case
where TPM2 encryption session feature is enabled the emulation allows to
obtain direct access to the virtual memory of the emulated computer and
to modify its flow of execution to obtain access to the operating system.

## How to build

To generate the USB key:

```
./setup.sh
```

To use a custom kernel you need to rebuild linux kernel with your custom config
file (Advise to disable IMA config) and use:

```
make -j `getconf _NPROCESSORS_ONLN` bindeb-pkg
```

and move linux-\*.deb package on parent directory to livebuild/config/packages.chroot/

to install the tpm_proxy lib and tool:

```
cd tpm_proxy
python3 setup.py install
```

## How to use

This project is composed to
- a patch qemu
- a tpm_proxy
- an example of script to root a linux emulator

TPMEE can be use as an USB stick:
In this case, an operating system is launched the login to use is:
- user: user
- password: live

To launch the proxy you have the command tpm_proxy

To launch the emulator an helper script is available at `~/exploit/TPMEE

```bash
TPMEE <disk_path> <tpm_path> [specific_options] [-u]
-u to enable uefi
```

tpm_proxy will produce a pcap file that you can analyse with Wireshark.

## Prerequisite

To use it, you should be able to boot on USB stick.
