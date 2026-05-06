CC      = gcc
CFLAGS  = -Wall -Wextra -pedantic -std=c11

OBJS = main.o tap.o protocol.o udp.o

TARGET  = vpnclient

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
