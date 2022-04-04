#!/bin/bash

set -e

GIT_QEMU=qemu
TPM_PROXY=tpm_proxy
KERNEL_EXPLOIT=tpm_kernel_exploit
BASE_DIR=$(pwd)

DIR_EXPLOIT=livebuild/config/includes.chroot_after_packages/etc/skel/exploit/

cd $GIT_QEMU
if [ ! -f "./patched" ];
then
  git apply "$BASE_DIR/$TPM_PROXY/qemu.patch"
  touch ./patched
fi
#./configure
#make -j16 qemu-system-x86_64
cd -

[ ! -d "$DIR_EXPLOIT/qemu" ] && mkdir "$DIR_EXPLOIT/qemu"
mount --bind "$GIT_QEMU/" "$DIR_EXPLOIT/qemu"
[ ! -d "$DIR_EXPLOIT/proxy" ] && mkdir "$DIR_EXPLOIT/proxy"
mount --bind "$TPM_PROXY/" "$DIR_EXPLOIT/proxy"

#cp "$GIT_QEMU/build/qemu-system-x86_64" "$DIR_EXPLOIT/qemu-system"
#cp "$TPM_PROXY/server.py" "$DIR_EXPLOIT/server.py"
#cp "$TPM_PROXY/requirement.txt" "$DIR_EXPLOIT/requirement.txt"
cp "$TPM_PROXY/test_proxy.py" "$DIR_EXPLOIT/test_proxy.py"
cp "$KERNEL_EXPLOIT/script.py" "$DIR_EXPLOIT/script.py"

cd livebuild

lb build

cd -

umount "$DIR_EXPLOIT/qemu"
umount "$DIR_EXPLOIT/proxy"
