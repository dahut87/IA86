CC=g++ -O2
LFLAGS=-lfinal -lkeystone -lstdc++ -lm -lcapstone -lunicorn -lz
OPTIONS=-std=c++17
DOCKER=docker run --name maker --rm -v $$(pwd):/data maker
START=./start.sh 

all: dockerfile files copy run

clean: dockerclean

clear:
	clear

dockerclean:
	(docker rmi $$(docker images | grep "^<none>" | awk '{print $$3}') --force;true)
	(docker rmi maker;true)
	docker image ls

dockerfile:
	docker build . -t maker

dockerfile_force: dockerclean dockerfile

files: ./ia86
    
ia86: ./ia86.cpp
	$(DOCKER) $(CC) $(OPTIONS) -o $@ $^ $(LFLAGS)

rerun:
	$(START)

run: clear delete files rerun	

stop:
	docker stop maker

delete:
	rm -rf ./ia86

copy:	libcapstone.so.4 libunicorn.so.1 libfinal.so.0.7.2 libkeystone.so.0 libc.musl-x86_64.so.1

libcapstone.so.4:
	${DOCKER} cp /usr/lib/libcapstone.so.4 /data/libcapstone.so.4

libunicorn.so.1:
	${DOCKER} cp /usr/lib/libunicorn.so.1 /data/libunicorn.so.1

libfinal.so.0.7.2:
	${DOCKER} cp /usr/lib/libfinal.so.0.7.2 /data/libfinal.so.0.7.2
	ln -s ./libfinal.so.0.7.2 ./libfinal.so.0 

libkeystone.so.0:
	${DOCKER} cp /usr/lib64/libkeystone.so.0 /data/libkeystone.so.0 

libc.musl-x86_64.so.1:
	${DOCKER} cp /lib/libc.musl-x86_64.so.1 /data/libc.musl-x86_64.so.1
