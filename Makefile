
all:
	gcc -Wall -Werror -g -o sniffer sniffer.c
	
clean:
	rm -rf sniffer
