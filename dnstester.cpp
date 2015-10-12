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
 
#include "dnstester.h"
#include <cstring>
#include <cstdio>
#include <cmath>
#include <sstream>
#include <iostream>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>

TestException::TestException(std::string what): what_{what} {}

const char* TestException::what() const noexcept {
	return what_.c_str();
}

DnsTester::DnsTester(struct in6_addr server_addr, uint16_t port, uint8_t id, uint16_t num_req, uint16_t num_burst, std::chrono::nanoseconds burst_delay):
					id_{id},
					num_req_{num_req},
					num_burst_{num_burst},
					burst_delay_{burst_delay},
					num_sent_{0}
	{
	/* Fill server sockaddr structure */
	memset(&server_, 0x00, sizeof(server_));
	server_.sin6_family = AF_INET6;
	server_.sin6_addr = server_addr;
	server_.sin6_port = htons(port);
	/* Create socket */
	int sockfd;
	if ((sockfd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		std::stringstream ss;
		ss << "Cannot create socket: " << strerror(errno);
		throw TestException{ss.str()};
	}
	sock_ = Socket{sockfd};
	/* Bind socket */
	struct sockaddr_in6 local_addr;
	memset(&local_addr, 0x00, sizeof(local_addr));
	local_addr.sin6_family = AF_INET6;  // IPv6
	local_addr.sin6_addr = in6addr_any; // To any valid IP address
	local_addr.sin6_port = htons(0);   // Get a random port
	if (::bind(sock_, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) == -1) {
		std::stringstream ss;
		ss << "Unable to bind socket: " << strerror(errno);
		throw TestException{ss.str()};
	}
	/* Set socket timeout */
	struct timeval tv;
	tv.tv_sec = recvfrom_timeout;
	tv.tv_usec = 0;
	if (::setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const void*>(&tv), sizeof(tv))) {
		throw TestException("Cannot set timeout: setsockopt failed");
	}
	/* Preallocate the test queries */
	for (int id = 0; id < num_req_; id++) {
		tests_.push_back(DnsQuery{});
	}
	/* Create the test queries */
	for (int id = 0; id < num_req_; id++) {
		DnsQuery& test = tests_[id];
		/* Filling the header */
		DNSHeader* header = reinterpret_cast<DNSHeader*>(test.query_data_);
		header->id(id);
		header->qr(0);
		header->opcode(DNSHeader::OpCode::Query);
		header->aa(false);
		header->tc(false);
		header->rd(true);
		header->ra(false);
		header->rcode(DNSHeader::RCODE::NoError);
		header->qdcount(1);
		header->ancount(0);
		header->nscount(0);
		header->arcount(0);
		/* Creating the question*/
		uint8_t* question = test.query_data_ + sizeof(DNSHeader);
		/* Creating the domain name */
		char query_addr[512];
		snprintf(query_addr, sizeof(query_addr), dns64_addr_format_string, id_, id / 256, id % 256);
		/* Convering the domain name to DNS Name format */
		char* label = strtok(query_addr, ".");
		while (label != nullptr) {
			*question = strlen(label);
			question += 1;
			memcpy(question, label, strlen(label));
			question += strlen(label);
			label = strtok(nullptr, ".");
		}
		*question = 0x00;
		question += 1;
		/* Setting the query type and class */
		*reinterpret_cast<uint16_t*>(question) = htons(QType::AAAA);
		question += sizeof(uint16_t);
		*reinterpret_cast<uint16_t*>(question) = htons(QClass::IN);
		question += sizeof(uint16_t);
		/* Parsing the raw packet into the DNSPacket structure */
		test.query_ = DNSPacket{test.query_data_, (size_t) (question - test.query_data_), sizeof(test.query_data_)};
		/* Setting flags */
		test.received_ = false;
		test.answered_ = false;
	}
}

void DnsTester::test() {
	for (int i = 0; i < num_burst_; i++) {
		/* Get query */
		m_.lock();
		DnsQuery& query = tests_[num_sent_];
		m_.unlock();
		/* Send query */
		if (::sendto(sock_, reinterpret_cast<const void*>(query.query_.begin_), query.query_.len_, 0, reinterpret_cast<const struct sockaddr*>(&server_), sizeof(server_)) != query.query_.len_) {
			std::cerr << "Can't send packet." << std::endl;
		}
		/* Store the time */
		query.time_sent_ = std::chrono::high_resolution_clock::now();
		m_.lock();
		num_sent_++;
		m_.unlock();
	}
}

void DnsTester::start() {
	/* Starting test packet sending */
	timer_ = std::unique_ptr<Timer>{new Timer{std::bind(&DnsTester::test, this), burst_delay_, (size_t) (num_req_ / num_burst_)}};
	timer_->start();
	/* Receiving answers */
	struct sockaddr_in6 sender;
	socklen_t sender_len;
	ssize_t recvlen;
	uint8_t answer_data[UDP_MAX_LEN];
	bool continue_receiving;
	
	continue_receiving = true;
	while (continue_receiving) {
		m_.lock();
		size_t remaining = num_req_ - num_sent_;
		m_.unlock();
		if (remaining == 0) {
			continue_receiving = false;
		}
		if ((recvlen = ::recvfrom(sock_, answer_data, sizeof(answer_data), 0, reinterpret_cast<struct sockaddr*>(&sender), &sender_len)) > 0) {
			/* Get the time of the receipt */
			std::chrono::high_resolution_clock::time_point time_received = std::chrono::high_resolution_clock::now();
			/* Test whether the answer came from the DUT */
			if (memcmp(reinterpret_cast<const void*>(&sender.sin6_addr), reinterpret_cast<const void*>(&server_.sin6_addr), sizeof(struct in6_addr)) != 0 || sender.sin6_port != server_.sin6_port) {
				throw TestException{"Received packet from other host than the DUT."};
			}
			/* Parse the answer */
			DNSPacket answer = DNSPacket{answer_data, (size_t) recvlen, sizeof(answer_data)};
			/* Test whether the query id is valid */
			if (answer.header_->id() >= tests_.size()) {
				std::stringstream ss;
				ss << "Invalid answer from server, bad id: " << answer.header_->id();
				throw TestException{ss.str()};
			}
			/* Find the corresponding query */
			m_.lock();
			DnsQuery& query = tests_[answer.header_->id()];
			m_.unlock();
			/* Set the received flag true */
			query.received_ = true;
			/* Calculate the Round-Trip-Time */
			query.rtt_ = std::chrono::duration_cast<std::chrono::nanoseconds>(time_received - query.time_sent_);
			/* Check whether there is an answer */
			query.answered_ = answer.header_->qr() == 1 && answer.header_->rcode() == DNSHeader::RCODE::NoError && answer.header_->ancount() > 0;
		} else {
			/* If the error is not caused by timeout, there is something wrong */
			if (errno != EWOULDBLOCK) {
				std::stringstream ss;
				ss << "Error in recvfrom: " << strerror(errno);
				throw TestException{ss.str()};
			}
		}
	}
}

void DnsTester::display() {
	uint16_t num_received, num_answered;
	double average, standard_deviation;
	num_received = 0;
	num_answered = 0;
	/* Number of received and answered queries */
	for (auto& query: tests_) {
		if (query.received_) {
			num_received++;
		}
		if (query.answered_) {
			num_answered++;
		}
	}
	/* Average */
	average = 0;
	for (auto& query: tests_) {
		if (query.received_) {
			average += (double) query.rtt_.count() / num_received;
		}
	}
	/* Standard deviation */
	standard_deviation = 0;
	for (auto& query: tests_) {
		if (query.received_) {
			standard_deviation += pow(query.rtt_.count() - average, 2.0);
		}
	}
	standard_deviation = sqrt(standard_deviation / num_received);
	/* Print results */
	printf("Sent queries: %zu\n", tests_.size());
	printf("Received answers: %hu (%.02f%%)\n", num_received, ((double) num_received / tests_.size()) * 100);
	printf("Valid answers: %hu (%.02f%%)\n", num_answered, (double) num_answered / tests_.size());
	printf("Average round-trip time: %.02f ms\n", average / 1000000.0);
	printf("Standard deviation of the round-trip time: %.02f ms\n", standard_deviation / 1000000.0);
}
