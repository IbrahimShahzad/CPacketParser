include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o WorkerThread.o WorkerThread.cpp
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o receiver.o receiver.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o rParser WorkerThread.o receiver.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm receiver.o
	rm WorkerThread.o
	rm rParser
