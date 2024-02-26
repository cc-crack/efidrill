#!/bin/bash
echo "BEGIN"
export WORKSPACE=/tiano
export PACKAGES_PATH=$WORKSPACE/edk2
cd /tiano/edk2
source edksetup.sh
build -p MdeModulePkg/MdeModulePkg.dsc -m myfault/src/myfault.inf
cp /tiano/Build/MdeModule/RELEASE_GCC5/X64/myfault.efi /tiano/edk2/myfault/bin/