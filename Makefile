CXX = g++
CXXFLAGS = -Wall -g

all:	oss	worker

oss:	oss.cpp
	$(CXX)	$(CXXFLAGS)	-o	oss	oss.cpp

worker:	worker.cpp
	$(CXX)	$(CXXFLAGS)	-o	worker	worker.cpp

clean:
	rm	-f	oss	worker

.PHONY:	all	clean
