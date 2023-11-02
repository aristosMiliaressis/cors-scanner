EXECUTABLE=cors-scanner
WINDOWS=$(EXECUTABLE).exe
LINUX=$(EXECUTABLE)

build: windows linux

windows:
	env GOOS=windows go build -v -o $(WINDOWS) -ldflags="-s -w" ./cmd/cors-scanner/main.go
	
linux:
	env GOOS=linux go build -v -o $(LINUX) -ldflags="-s -w" ./cmd/cors-scanner/main.go

clean:
	rm -f $(WINDOWS) $(LINUX) 
