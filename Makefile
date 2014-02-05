TARGET=bpag
CC=gcc
CFLAGS=-I. -O3
LINK=gcc -o
LDFLAGS=-lpthread -lcrypto -lm
SRCDIR=src
OBJDIR=obj

SRC=$(wildcard $(SRCDIR)/*.c)
INC=$(wildcard $(SRCDIR)/*.h)
OBJ=$(SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean
all: $(TARGET)

clean:
	rm -rf $(OBJ)
	rm -rf $(TARGET)

$(TARGET): $(OBJ)
	$(LINK) $@ $(OBJ) $(LDFLAGS)
	

$(OBJ): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

