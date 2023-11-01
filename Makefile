EXECUTABLE=cors-scanner
WINDOWS=$(EXECUTABLE).exe
LINUX=$(EXECUTABLE)

build: windows linux

windows: $(WINDOWS)

linux: $(LINUX)

$(WINDOWS):
	env GOOS=windows go build -v -o $(WINDOWS) -ldflags="-s -w" ./cmd/main/main.go

$(LINUX):
	env GOOS=linux go build -v -o $(LINUX) -ldflags="-s -w" ./cmd/main/main.go

clean:
	rm -f $(WINDOWS) $(LINUX) 
