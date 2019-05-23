include /usr/local/etc/PcapPlusPlus.mk

all:
	g++ $(PCAPPP_INCLUDES) -O2 -std=c++0x -c -o parser.o parser.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o parser parser.o $(PCAPPP_LIBS)

clean:
	rm parser.o
	rm parser


