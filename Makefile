all: main

main: main.cpp
	g++ -o bin/prog main.cpp -L./libs/libpcap-1.10.5 -lpcap -L./libs/dbus -ldbus-1

clean: 
	rm -f bin/*
