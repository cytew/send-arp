LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o sendarp.o
	g++ -o send-arp-test main.o arphdr.o ethhdr.o ip.o mac.o sendarp.o -lpcap

main.o: ethhdr.h arphdr.h main.cpp
	g++ -std=c++11 -c -o main.o main.cpp

arphdr.o: arphdr.cpp arphdr.h mac.h	ip.h
	g++ -std=c++11 -c arphdr.cpp

ethhdr.o: ethhdr.cpp ethhdr.h mac.h
	g++ -std=c++11 -c ethhdr.cpp

mac.o: mac.cpp mac.h
	g++ -std=c++11 -c mac.cpp

ip.o: ip.cpp ip.h
	g++ -std=c++11 -c ip.cpp

sendarp.o: sendarp.cpp sendarp.h
	g++ -std=c++11 -c sendarp.cpp

clean:
	rm -f send-arp-test *.o
