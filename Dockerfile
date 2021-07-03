FROM alpine:3.12.0
 
ENV UNICORN_VER  1.0.3
ENV CAPSTONE_VER 4.0.2
ENV KEYSTONE_VER 0.9.2

RUN echo "http://alpine.42.fr/v3.12/main" > /etc/apk/repositories
RUN echo "http://alpine.42.fr/v3.12/community" >> /etc/apk/repositories
RUN apk --no-cache update
RUN apk --no-cache upgrade
RUN apk --no-cache add bash util-linux coreutils curl make cmake gcc g++ libstdc++ libgcc zlib-dev \
		       git sed tar wget gzip indent binutils hexdump dos2unix xxd autoconf automake autoconf-archive\ 
                       libtool linux-headers ncurses-dev
WORKDIR /usr/src/
RUN git clone git://github.com/gansm/finalcut.git 
WORKDIR /usr/src/finalcut
RUN autoreconf --install --force && ./configure --prefix=/usr && make && make install

WORKDIR /usr/src
RUN wget https://github.com/unicorn-engine/unicorn/archive/${UNICORN_VER}.tar.gz && tar -xzf ${UNICORN_VER}.tar.gz
WORKDIR /usr/src/unicorn-${UNICORN_VER}
RUN UNICORN_ARCHS="x86" ./make.sh && UNICORN_ARCHS="x86" ./make.sh install

RUN apk --no-cache add python3-dev
 
WORKDIR /usr/src
RUN wget https://github.com/keystone-engine/keystone/archive/${KEYSTONE_VER}.tar.gz && tar -xzf ${KEYSTONE_VER}.tar.gz
RUN ls
WORKDIR /usr/src/keystone-${KEYSTONE_VER}
RUN mkdir build
WORKDIR /usr/src/keystone-${KEYSTONE_VER}/build
RUN cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="X86" -G "Unix Makefiles" ..
RUN make -j8
RUN make install

WORKDIR /usr/src
RUN wget https://github.com/aquynh/capstone/archive/${CAPSTONE_VER}.tar.gz && tar -xzf ${CAPSTONE_VER}.tar.gz
WORKDIR /usr/src/capstone-${CAPSTONE_VER}
RUN CAPSTONE_ARCHS="x86" CAPTONE_X86_REDUCE="yes" ./make.sh && CAPSTONE_ARCHS="x86" CAPTONE_X86_REDUCE="yes" ./make.sh install

RUN adduser -D -H -u 502 utilisateur
RUN adduser -D -H -u 1000 utilisateurs
RUN mkdir /data
WORKDIR /data

ENV LD_LIBRARY_PATH /usr/lib64
