CC=g++ -O2
LFLAGS=-lfinal -lkeystone -lstdc++ -lm -lcapstone -lunicorn -lz
OPTIONS=-std=c++17
DOCKER=docker run -it -e COLUMNS="$$(tput cols)" -e LINES="$$(tput lines)" --name maker --rm -v $$(pwd):/data maker
XTERM=terminator -f -e 

all: dockerfile files run

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
	$(XTERM) '$(DOCKER) bash -c "sleep 0.4;./ia86"'

run: clear delete files rerun	

stop:
	docker stop maker

delete:
	rm -rf ./ia86
