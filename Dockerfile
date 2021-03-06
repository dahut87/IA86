FROM alpine:3.13.0
 
ENV UNICORN_VER  1.0.3
ENV CAPSTONE_VER 4.0.2
ENV KEYSTONE_VER 0.9.2

RUN echo "http://alpine.42.fr/v3.13/main" > /etc/apk/repositories
RUN echo "http://alpine.42.fr/v3.13/community" >> /etc/apk/repositories
RUN apk --no-cache update
RUN apk --no-cache upgrade
RUN apk --no-cache add bash util-linux coreutils curl make cmake gcc g++ libstdc++ libgcc \
		       git sed tar wget gzip indent binutils autoconf automake autoconf-archive\ 
                       libtool linux-headers ncurses-dev python3-dev

WORKDIR /usr/src
RUN wget https://github.com/unicorn-engine/unicorn/archive/${UNICORN_VER}.tar.gz && tar -xzf ${UNICORN_VER}.tar.gz
WORKDIR /usr/src/unicorn-${UNICORN_VER}
RUN UNICORN_ARCHS="x86" ./make.sh && UNICORN_ARCHS="x86" ./make.sh install

WORKDIR /usr/src
RUN wget https://github.com/keystone-engine/keystone/archive/${KEYSTONE_VER}.tar.gz && tar -xzf ${KEYSTONE_VER}.tar.gz
RUN ls
WORKDIR /usr/src/keystone-${KEYSTONE_VER}
RUN mkdir build
WORKDIR /usr/src/keystone-${KEYSTONE_VER}/build
RUN cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="X86" -G "Unix Makefiles" ..
RUN make -j8
RUN make install
RUN MAKE_INSTALL_PREFIX=/usr CMAKE_BUILD_TYPE=Release BUILD_SHARED_LIBS=ON LLVM_TARGETS_TO_BUILD="X86" ../make-lib.sh
RUN cp /usr/src/keystone-0.9.2/build/llvm/lib64/libkeystone.a /usr/lib64/

WORKDIR /usr/src
RUN wget https://github.com/aquynh/capstone/archive/${CAPSTONE_VER}.tar.gz && tar -xzf ${CAPSTONE_VER}.tar.gz
WORKDIR /usr/src/capstone-${CAPSTONE_VER}
RUN CAPSTONE_ARCHS="x86" CAPTONE_X86_REDUCE="yes" ./make.sh && CAPSTONE_ARCHS="x86" CAPTONE_X86_REDUCE="yes" ./make.sh install

WORKDIR /usr/src
RUN git clone https://github.com/bk192077/struct_mapping.git
WORKDIR /usr/src/struct_mapping
RUN mkdir build
WORKDIR /usr/src/struct_mapping/build
RUN cmake .. && cmake --build . && cmake --install .

WORKDIR /usr/src
RUN git clone https://github.com/dahut87/finalcut.git 
WORKDIR /usr/src/finalcut
RUN autoreconf --install --force && ./configure --prefix=/usr && make && make install

WORKDIR /usr/src
RUN git clone https://github.com/madler/zlib.git
WORKDIR /usr/src/zlib
RUN ./configure && make && make install prefix=/usr/

RUN apk --no-cache add ncurses-static

RUN adduser -D -H -u 502 utilisateur
RUN adduser -D -H -u 1000 utilisateurs
RUN mkdir /data
WORKDIR /data

ENV LD_LIBRARY_PATH /usr/lib64
