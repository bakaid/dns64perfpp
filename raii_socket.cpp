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
 
#include <cstring>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "raii_socket.h"

SocketException::SocketException(std::string what): what_{what} {}

const char* SocketException::what() const noexcept {
	return what_.c_str();
}

Socket::Socket(int sockfd): sockfd_{sockfd}, closed_{false} {

}

Socket::~Socket() {
	if (!closed_ && sockfd_ != -1) {
		::close(sockfd_);
	}
}

Socket::Socket(Socket&& rhs): sockfd_{rhs.sockfd_} {
	rhs.sockfd_ = -1;
}

Socket& Socket::operator=(Socket&& rhs) {
	sockfd_ = rhs.sockfd_;
	rhs.sockfd_ = -1;
	return *this;
}

void Socket::close() {
	if (sockfd_ == -1) {
		throw SocketException{"No valid managed socket."};
	}
	if (::close(sockfd_) == -1) {
		throw SocketException{strerror(errno)};
	}
	closed_ = true;
}

Socket::operator int() {
	return sockfd_;
}
