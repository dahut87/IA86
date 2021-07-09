CC=g++ -O2
LFLAGS=-lfinal -lkeystone -lstdc++ -lm -lcapstone -lunicorn -lz
OPTIONS=-std=c++17
DOCKER=docker run -it -e COLUMNS="$$(tput cols)" -e LINES="$$(tput lines)" --name maker --rm -v $$(pwd):/data maker
XTERM=terminator -f -e 

all: dockerfile files run

clean: dockerclean

dockerclean:
	(docker rmi $$(docker images | grep "^<none>" | awk '{print $$3}') --force;true)
	docker image ls

dockerfile:
	docker build . -t maker

files: ./ia86
    
ia86: ./ia86.cpp
	$(DOCKER) $(CC) $(OPTIONS) -o $@ $^ $(LFLAGS)

run:
	$(XTERM) '$(DOCKER) bash -c "sleep 0.4;./ia86"'

rerun: delete files run	

stop:
	docker stop maker

delete:
	rm -rf ./ia86
