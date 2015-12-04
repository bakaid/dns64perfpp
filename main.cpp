/* dns64perf++ - C++11 DNS64 performance tester
 * Based on dns64perf by Gabor Lencse <lencse@sze.hu> (http://ipv6.tilb.sze.hu/dns64perf/)
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
#include <ctime>
#include <cmath>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dnstester.h"


int main(int argc, char* argv[]) {
	struct in6_addr server_addr;
	uint16_t port;
	uint32_t ip;
	uint8_t netmask;
	uint32_t num_req, num_burst;
	uint64_t burst_delay;
	struct timeval timeout;
	if (argc < 8) {
		std::cerr << "Usage: dns64perf++ <server> <port> <subnet> <number of requests> <burst size> <delay between bursts in ns> <timeout in s>" << std::endl;
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
	/* Subnet */
	uint8_t temp[4];
	if (sscanf(argv[3], "%hhu.%hhu.%hhu.%hhu/%hhu", temp, temp+1, temp+2, temp+3, &netmask) != 5) {
		std::cerr << "Bad subnet." << std::endl;
		return -1;
	}
	if (netmask > 32) {
		std::cerr << "Bad netmask." << std::endl;
		return -1;
	}
	ip = ((temp[0] << 24) | (temp[1] << 16) | (temp[2] << 8) | temp[3]) & ~(((uint64_t) 1 << (32-netmask))-1);
	/* Number of requests */
	if (sscanf(argv[4], "%u", &num_req) != 1) {
		std::cerr << "Bad number of requests, must be between 0 and 2^32." << std::endl;
		return -1;
	}
	if (num_req > ((uint64_t) 1 << (32-netmask))) {
		std::cerr << "The number of requests is higher than the avaliable IPs in the subnet." << std::endl;
		return -1;
	}
	/* Burst size */
	if (sscanf(argv[5], "%u", &num_burst) != 1) {
		std::cerr << "Bad burst size, must be between 0 and 2^32." << std::endl;
		return -1;
	}
	/* Burst size */
	if (sscanf(argv[6], "%lu", &burst_delay) != 1) {
		std::cerr << "Bad delay between bursts." << std::endl;
		return -1;
	}
	/* Timeout */
	double timeout_, s, us;
	if (sscanf(argv[7], "%lf", &timeout_) != 1) {
		std::cerr << "Bad timeout." << std::endl;
		return -1;
	}
	us = modf(timeout_, &s) * 1000000;
	timeout.tv_sec = (time_t) s;
	timeout.tv_usec = (suseconds_t) us;
	try {
		DnsTester tester{server_addr, port, ip, netmask, num_req, num_burst, std::chrono::nanoseconds{burst_delay}, timeout};
		tester.start();
		tester.display();
		tester.write("dns64perf.csv");
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return 0;
}
