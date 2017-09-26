/* dns64perf++ - C++14 DNS64 performance tester
 * Based on dns64perf by Gabor Lencse <lencse@sze.hu>
 * (http://ipv6.tilb.sze.hu/dns64perf/)
 * Copyright (C) 2017  Daniel Bakai <bakaid@kszk.bme.hu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/** @file
 *  @brief Header for a RAII socket wrapper
 */

#ifndef SOCKET_H_INCLUDED_
#define SOCKET_H_INCLUDED_

#include <exception>
#include <string>

/**
 * An std::exception class for the Socket.
 */
class SocketException : public std::exception {
private:
  std::string what_; /**< Exception string */
public:
  /**
   * A constructor.
   * @param what the exception string
   */
  SocketException(std::string what);

  /**
   * A getter for the exception string.
   * @return the exception string
   */
  const char *what() const noexcept override;
};

/**
 * Class for a RAII socket wrapper
 */
class Socket {
private:
  int sockfd_;  /**< The managed socket */
  bool closed_; /**< Flag to mark whether the socket has already been closed */
public:
  /**
   * A constructor.
   * @param sockfd the socket to manage
   */
  Socket(int sockfd = -1);

  /**
   * A destructor. Closes the socket if applicable.
   */
  ~Socket();

  /**
   * Copy constructor. Explicitly deleted.
   */
  Socket(const Socket &) = delete;

  /**
   * Copy assignment operator. Explicitly deleted.
   */
  Socket &operator=(const Socket &) = delete;

  /**
   * Move constructor.
   * @param rhs the Socket to move from
   */
  Socket(Socket &&rhs);

  /**
   * Move assignment operator.
   * @param rhs the Socket to move from
   * @return reference to the Socket
   */
  Socket &operator=(Socket &&rhs);

  /**
   * Explicitly closes the socket.
   */
  void close();

  /**
   * Int conversion operator.
   */
  operator int();
};

#endif
