network_hw1: main.cpp
	gcc -o network_hw1 main.cpp -L./ -lpcap

clean:
	rm -f *.o network_hw1

