EXECUTABLE=cors-scanner
WINDOWS=$(EXECUTABLE).exe
LINUX=$(EXECUTABLE)

install: build
	mv $(LINUX) ${GOPATH}/bin

build: windows linux

windows:
	env GOOS=windows go build -v -o $(WINDOWS) -ldflags="-s -w" .
	
linux:
	env GOOS=linux go build -v -o $(LINUX) -ldflags="-s -w" .

clean:
	rm -f $(WINDOWS) $(LINUX) 
