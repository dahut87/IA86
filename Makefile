CC=g++ -O2
LFLAGS=-lfinal -lkeystone -lstdc++ -lm -lcapstone -lunicorn
DOCKER=docker run -it --name maker --rm -v $$(pwd):/data maker

all: dockerfile files run

dockerfile:
	docker build . -t maker

files: ./test
    
test: ./test.cpp
	$(DOCKER) $(CC) -o $@ $^ $(LFLAGS)

run:
	$(DOCKER) ./test

rerun: delete files run	

delete:
	rm -rf ./test
