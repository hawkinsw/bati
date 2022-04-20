# There appears to be some interest in != as a POSIX-compliant
# way to get output from a shell command in to a make variable.
# So, let's stick with that.
SOURCES!=find . -name '*.go'

all: bati.exe

bati.exe: ${SOURCES}
	go build ./main.go
	mv main bati.exe

clean:
	go clean
	rm -f bati.exe
