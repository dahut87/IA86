CC=g++ -O2
LFLAGS=-lfinal -lkeystone -lstdc++ -lm -lcapstone -lunicorn
DOCKER=docker run -it -e COLUMNS="$$(tput cols)" -e LINES="$$(tput lines)" --name maker --rm -v $$(pwd):/data maker
XTERM=terminator -f -e 

all: dockerfile files run

dockerfile:
	docker build . -t maker

files: ./ia86
    
ia86: ./ia86.cpp
	$(DOCKER) $(CC) -o $@ $^ $(LFLAGS)

run:
	$(XTERM) '$(DOCKER) bash -c "sleep 0.4;./ia86"'

rerun: delete files run	

stop:
	docker stop maker

delete:
	rm -rf ./ia86
