all: main

main: main.cpp
	g++ -o bin/prog main.cpp -lpcap

clean: 
	rm -f bin/*