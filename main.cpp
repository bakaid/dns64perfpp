/* dns64perf++ - C++11 DNS64 performance tester
 * Based on dns64perf by Gabor Lencse <lencse@sze.hu> (http://dev.tilb.sze.hu/dns64perf/)
 * Copyright (C) 2015  Daniel Bakai <bakaid@kszk.bme.hu>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
 
#include <iostream>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dnstester.h"


int main(int argc, char* argv[]) {
	struct in6_addr server_addr;
	uint16_t port;
	uint8_t id;
	uint16_t num_req, num_burst;
	uint64_t burst_delay;
	if (argc < 7) {
		std::cerr << "Usage: dns64perf++ <server> <port> <id> <number of requests> <burst size> <delay between bursts in ns>" << std::endl;
		return -1;
	}
	/* Server address */
	if (inet_pton(AF_INET6, argv[1], reinterpret_cast<void*>(&server_addr)) != 1) {
		std::cerr << "Bad server adddress." << std::endl;
		return -1;
	}
	/* Port */
	if (sscanf(argv[2], "%hu", &port) != 1) {
		std::cerr << "Bad port." << std::endl;
		return -1;
	}
	/* ID */
	if (sscanf(argv[3], "%hhu", &id) != 1) {
		std::cerr << "Bad id." << std::endl;
		return -1;
	}
	/* Number of requests */
	if (sscanf(argv[4], "%hu", &num_req) != 1) {
		std::cerr << "Bad number of requests, must be between 0 and 65535." << std::endl;
		return -1;
	}
	/* Burst size */
	if (sscanf(argv[5], "%hu", &num_burst) != 1) {
		std::cerr << "Bad burst size, must be between 0 and 65535." << std::endl;
		return -1;
	}
	/* Burst size */
	if (sscanf(argv[6], "%lu", &burst_delay) != 1) {
		std::cerr << "Bad delay between bursts." << std::endl;
		return -1;
	}
	try {
		DnsTester tester{server_addr, port, id, num_req, num_burst, std::chrono::nanoseconds{burst_delay}};
		tester.start();
		tester.display();
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return 0;
}
