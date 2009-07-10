CXXFLAGS=-O -Wall -Wextra -g -lsmbclient -lid3 -lsqlite3

all: indexer

clean:
	rm -f *.o

distclean: clean
	rm indexer

.PHONY: all clean distclean
