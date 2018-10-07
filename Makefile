# dns64perf++ - C++14 DNS64 performance tester
# Based on dns64perf by Gabor Lencse <lencse@sze.hu>
# (http://ipv6.tilb.sze.hu/dns64perf/)
# Copyright (C) 2017  Daniel Bakai <bakaid@kszk.bme.hu>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

BINARY = dns64perf++
OBJECTS = main.o timer.o dns.o dnstester.o raii_socket.o spin_sleep.o
HEADERS = timer.h dns.h dnstester.h raii_socket.h spin_sleep.hpp

CXX = clang++
CXXFLAGS = -std=c++14 -O3 -Wall -Wdeprecated -pedantic -g
LDFLAGS = -lm -lpthread

PREFIX = /usr

ifeq ($(DEBUG), 1)
    CXXFLAGS += -DDEBUG
endif

ifeq ($(IPV4), 1)
    CXXFLAGS += -DDNS64PERFPP_IPV4
endif

.PHONY: all clean

all: $(BINARY)

install: all
	install -m 0755 $(BINARY) $(PREFIX)/sbin

clean:
	rm -f $(BINARY) $(OBJECTS)

$(BINARY): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@
