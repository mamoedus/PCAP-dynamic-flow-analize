all: main

main: main.cpp
	cd libs/dbus && ln -s libdbus-1.so.3.38.3 libdbus-1.so
	
	g++ -o bin/prog main.cpp -L./libs/libpcap-1.10.5 -lpcap -L./libs/dbus -ldbus-1

clean: 
	rm -f bin/*
