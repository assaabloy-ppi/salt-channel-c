#!/bin/sh

if [ ! -d "cmocka-1.1.1/build" ]; then
    echo "Building cmocka from source."
    wget https://cmocka.org/files/1.1/cmocka-1.1.1.tar.xz
    tar -xJvf cmocka-1.1.1.tar.xz
    cd cmocka-1.1.1 && mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
    cd ../..
else
    echo "Using cmocka from cache."
    cd cmocka-1.1.1/build
    sudo make install
    cd ../..
fi

if [ ! -d "$HOME/libsodium/lib" ]; then
  wget https://github.com/jedisct1/libsodium/releases/download/1.0.11/libsodium-1.0.11.tar.gz
  tar xvfz libsodium-1.0.11.tar.gz
  cd libsodium-1.0.11
  ./configure
  make
  sudo make install
else
  echo 'Using cached directory.'
  cd libsodium-1.0.11
  sudo make install
  cd ../
fi