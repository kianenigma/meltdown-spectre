CFLAGS += -O3
CFLAGS += -Iinclude
CFLAGS += -D_GNU_SOURCE=1

LDFLAGS += -no-pie

all: meltdown spectre


meltdown: main-meltdown.o
	${CC} $< -o $@ ${LDFLAGS} ${CFLAGS} ${LIBS}

spectre: main-spectre.o
	${CC} $< -o $@ ${LDFLAGS} ${CFLAGS} ${LIBS}

%.o: %.c
	${CC} -c $< -o $@ ${CFLAGS} -MT $@ -MMD -MP -MF $(@:.o=.d)

clean:
	rm -f meltdown spectre *.o *.d
