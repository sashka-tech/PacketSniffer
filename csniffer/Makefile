
IDIR = include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR =lib
_SDIR = sniffer.c
SDIR = src
SRC = $(patsubst %,$(SDIR)/%,$(_SDIR))
_HDIR = packetHeader.h packetDecoder.h packetDump.h
HDIR = include
LIBS=-lpcap

DEPS = $(patsubst %,$(HDIR)/%,$(_HDIR))
_OBJ = sniffer.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

.PHONY: all   
      all: $(OBJ) sniffer 

$(OBJ): $(SRC) $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS)

sniffer: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
