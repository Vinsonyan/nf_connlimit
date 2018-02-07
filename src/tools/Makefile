SOURCES:=$(wildcard *.c)
TARGETLIST:=$(patsubst %.c,%,$(SOURCES))
CFLAGS += -g
all:${TARGETLIST}

.PHONY:clean

clean:
	$(foreach TARGET,${TARGETLIST},rm -f $(TARGET);)
