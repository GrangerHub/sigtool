TARGET = sigtool
SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,${SRCS})

CFLAGS += -std=gnu99 -pedantic -Wall -Wextra -Werror -Wno-pointer-sign
CFLAGS += $(shell pkg-config --cflags nettle)
CFLAGS += $(shell pkg-config --cflags hogweed)

LDFLAGS += -lgmp
LDFLAGS += $(shell pkg-config --libs nettle)
LDFLAGS += $(shell pkg-config --libs hogweed)

.PHONY: all
all: $(TARGET)
$(TARGET): $(OBJS)
clean:
	$(Q) rm -f $(OBJS) $(TARGET)
