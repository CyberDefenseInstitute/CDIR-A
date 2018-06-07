CC := g++
CFLAGS := -std=gnu++1z -O3 -static
INCLUDE := -I./include/
LIBS := lib/*.cpp
SRCS := src/*.cpp
INCLUDES := include/*.h
#DEBUG := -DDEBUG

all: $(SRCS) $(INCLUDES) $(LIBS)
#	$(CC) $(DEBUG) $(CFLAGS) $(INCLUDE) $(LIBS) $(SRCS) -o mft
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) $(SRCS) -o mft
