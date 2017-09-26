dns64perf++
===========

A C++14 DNS64 tester.

Introduction
------------

dns64perf++ is a tool for measuring DNS64 server performance.


Method
------

dns64perf++ sends AAAA queries for domain names generated on-the-fly, incrementally from a specific subnet in the form {000..255}-{000..255}-{000..255}-{000..255}.dns64perf.test.

It uses a function execution time-compensated timer on a worker thread to send these requests at a specific frequency.

Below 200 Hz (>5 ms) it uses std::this_thread::sleep_for() for timing, over 200 Hz it uses active sleep (a spinlock) to ensure better timer accuracy.

The requests can be sent in bursts, in which case the specified number of requests are sent at every tick of the timer.

If the function execution takes longer than the avaliable time specified for its execution, then the application writes a "Can't keep up" message to the standard error output.

If the timer accuracy is off by more than 5%, then the application writes an error message to the standard output.

The main thread starts the timer, then receives the replies from the DUT, calculating the Round-trip time of the reply, and checking whether there is an answer (ancount > 0) in the reply.

After the last query has been sent, the main thread waits for 2 more seconds for replies, then calculates the parameteres of the test and writes the raw test data to a file named dns64perf.csv.

Build
-----
dns64perf++ is written in C++14 and requires >=clang-3.5 or >=gcc-4.8.3 to compile.

To compile and install dns64perf++ issue:

	make
	sudo make install

Usage
-----
dns64perf++ can be parameterized using command line arguments. All the arguments are mandatory.

If you installed dns64perf++ you can start a measurement using:

	dns64perf++ <server> <port> <subnet> <number of requests> <burst size> <number of threads> <delay between bursts in ns> <timeout in s>

__server__: the IPv6 address of the DUT

__port__: the port on which the DNS64 server listens

__subnet__: the subnet to use in the measurement, e.g.: 10.0.0.0/8, 192.168.0.0/24

__number of requests__: the number of requests to send, must be between 1 and the maximum number of IPv4 addresses in the specified subnet

__burst size__: the number of requests to send at every timer tick, must be the divisor of the number of requests

__number of threads__: the number of threads to use

__delay between bursts in ns__: 1/< timer frequency > in nanoseconds

__timeout in s__: wait no more than this for an answer
