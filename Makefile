CC=g++ -O2
LFLAGS=-lfinal -lkeystone -lstdc++ -lm -lcapstone -lunicorn
DOCKER=docker run -it -e COLUMNS="$$(tput cols)" -e LINES="$$(tput lines)" --name maker --rm -v $$(pwd):/data maker
XTERM=terminator -f -e 

all: dockerfile files run

dockerfile:
	docker build . -t maker

files: ./test
    
test: ./test.cpp
	$(DOCKER) $(CC) -o $@ $^ $(LFLAGS)

run:
	$(XTERM) '$(DOCKER) bash -c "sleep 0.4;./test"'

rerun: delete files run	

stop:
	docker stop maker

delete:
	rm -rf ./test
