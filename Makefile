TARGET = sigtool
OBJ = sigtool.o

CC = gcc

CFLAGS = -g -Wall -Wno-pointer-sign
CFLAGS += $(shell pkg-config --cflags nettle)
CFLAGS += $(shell pkg-config --cflags hogweed)

LDFLAGS = -g -lgmp
LDFLAGS += $(shell pkg-config --libs nettle)
LDFLAGS += $(shell pkg-config --libs hogweed)

ifeq ("$(V)","1")
Q :=
vecho := @true
else
Q := @
vecho := @echo
endif

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJ)
	$(vecho) "LD $@"
	$(Q) $(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(vecho) "CC $<"
	$(Q) $(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(Q) rm -f *.o $(TARGET)
