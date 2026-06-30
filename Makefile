# Build the VBS-style secret-delivery PoC against a *built* TSS.CPP tree.
#
# Point TSS_CPP at the TSS.MSR/TSS.CPP directory. Build TSS.CPP first:
#     cd TSS.MSR/TSS.CPP && make config=release      # -> bin/tss.a
# (debug build produces bin/tssd.a; set TSS_A=bin/tssd.a below.)
#
# Then:
#     make TSS_CPP=/path/to/TSS.MSR/TSS.CPP

TSS_CPP ?= ../TSS.MSR/TSS.CPP
TSS_A   ?= $(TSS_CPP)/bin/tss.a

CXX      ?= g++
CXXFLAGS := -std=c++11 -Wall -I$(TSS_CPP)/include
LIBS     := $(TSS_A) -lcrypto -ldl -lpthread

vbs_poc: vbs_poc.cpp
	$(CXX) $(CXXFLAGS) -o $@ vbs_poc.cpp $(LIBS)

clean:
	rm -f vbs_poc

.PHONY: clean
