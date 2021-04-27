CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -O2
LDFLAGS =
LIBS = -lstdc++fs

SRCS = main.cpp
OBJS = $(subst .cpp,.o, $(SRCS))

all: serwer

serwer: $(OBJS)
		$(CXX) $(LDFLAGS) -o serwer $(OBJS) $(LIBS)

main.o: main.cpp
		$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f $(OBJS) serwer
