SRC=dns-monitor.c
OUT=dns-monitor
CC=gcc
CFLAGS=-Wall 

run:
	$(CC) $(SRC) $(CFLAGS) -o $(OUT) -lpcap

clean:
	rm $(OUT)