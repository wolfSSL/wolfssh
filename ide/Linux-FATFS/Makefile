# Compiler and flags
CC = gcc
CFLAGS = -g -Wall -O2 -fPIC
LDFLAGS = -shared

# Source files
SRCS = ff.c ffunicode.c fatfs_example.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target library
TARGET = libfatfs.so

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
