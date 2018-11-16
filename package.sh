#!/bin/bash

packageName=network-analysis
version=1.0

if [ ! -f "network-analysis" ]
then
  echo "Error: You must build the project before making a Debian package"
  exit
fi

mkdir ${packageName}_${version}
mkdir ${packageName}_${version}/usr
mkdir ${packageName}_${version}/usr/local
mkdir ${packageName}_${version}/usr/local/bin
cp network-analysis ${packageName}_${version}/usr/local/bin

mkdir ${packageName}_${version}/DEBIAN
echo "Package: $packageName" >> ${packageName}_${version}/DEBIAN/control
echo "Version: $version" >> ${packageName}_${version}/DEBIAN/control
echo "Section: base" >> ${packageName}_${version}/DEBIAN/control
echo "Priority: optional" >> ${packageName}_${version}/DEBIAN/control
echo "Architecture: amd64" >> ${packageName}_${version}/DEBIAN/control
echo "Depends:" >> ${packageName}_${version}/DEBIAN/control
echo "Maintainer: Gautier Jousset <gautier.jousset@epitech.eu>, Julien Luino <julien.luino@epitech.eu>" >> ${packageName}_${version}/DEBIAN/control
echo "Description: Network Security 1 module project" >> ${packageName}_${version}/DEBIAN/control
echo " Socket reader application" >> ${packageName}_${version}/DEBIAN/control

dpkg-deb --build ${packageName}_${version}
rm -rf ${packageName}_${version}
