CC=g++
all: server.o dns.o dns-zone.o
	$(CC) server.o dns.o dns-zone.o -o server

dns.o: dns.cpp
	$(CC) -c dns.cpp -o dns.o

dns-zone.o: dns-zone.cpp
	$(CC) -c dns-zone.cpp -o dns-zone.o


server.o: server.cpp
	$(CC) -c server.cpp -o server.o