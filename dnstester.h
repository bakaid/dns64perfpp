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

/** @file 
 *  @brief Header for the DNS tester class
 */

#ifndef DNS_TESTER_H_INCLUDED_
#define DNS_TESTER_H_INCLUDED_

#include <memory>
#include <chrono>
#include <exception>
#include <string>
#include <vector>
#include <mutex>
#include <netinet/in.h>
#include <stdint.h>
#include "dns.h"
#include "timer.h"
#include "raii_socket.h"

static const size_t UDP_MAX_LEN = 512;
static const char* dns64_addr_format_string = "10-%hhu-%hhu-%hhu.dns64perf.test.";
static const uint8_t recvfrom_timeout = 2;

/**
 * An std::exception class for the DnsTester.
 */
class TestException: public std::exception
{
	private:
		std::string what_; /**< Exception string */
	public:
		/**
		 * A constructor.
		 * @param what the exception string
		 */
		TestException(std::string what);
		
		/**
		 * A getter for the exception string.
		 * @return the exception string
		 */
		const char* what() const noexcept override;
};

/**
 * Class to represent one test query
 */
struct DnsQuery {
		std::unique_ptr<uint8_t> query_data_; /**< Array to store the packet */
		DNSPacket query_; /**< The DNSPacket representation of the query */
		std::chrono::high_resolution_clock::time_point time_sent_; /**< Timestamp of the send time */
		bool received_; /**< Flag to mark whether an answer has been received */
		bool answered_; /**< Flag to mark whether the answer was valid */
		std::chrono::nanoseconds rtt_; /**< Round-trip time of the query */
		
		DnsQuery(uint8_t* query_data, size_t query_data_len, size_t query_data_maxlen);
};

/**
 * Class to represent a test
 */
class DnsTester {
	private:
		struct sockaddr_in6 server_; /**< Address of the server */
		uint8_t id_; /**< ID of the test */
		uint16_t num_req_; /**< Number of requests */
		uint16_t num_burst_; /**< Burst size */
		std::chrono::nanoseconds burst_delay_; /**< Time between bursts in nanoseconds */
		Socket sock_; /**< Socket for sending and receiving queries */
		std::vector<DnsQuery> tests_; /**< Test queries */
		uint16_t num_sent_; /**< Number of sent queries so far */
		std::mutex m_; /**< Mutex for accessing queries */
		std::unique_ptr<Timer> timer_; /**< Timer for scheduling queries */
		
		/**
		 * Sends a burst
		 */
		void test();
	public:
		/**
		 * Constructor.
		 * @param server_addr address of the server
		 * @param port port of the server
		 * @param id id of the test
		 * @param num_req number of requests
		 * @param num_burst size of burst
		 * @param burst_delay delay between bursts in nanoseconds
		 */
		DnsTester(struct in6_addr server_addr, uint16_t port, uint8_t id, uint16_t num_req, uint16_t num_burst, std::chrono::nanoseconds burst_delay);
		
		/**
		 * Starts the test
		 */
		void start();
		
		/**
		 * Displays the test results
		 */
		void display();
		
		/**
		 * Writes the test results to a file.
		 * @param filename the file to write to
		 */
		void write(const char* filename);
};

#endif