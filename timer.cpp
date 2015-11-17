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
 
#include "timer.h"

#include <iostream>
#include "spin_sleep.hpp"

Timer::Timer(std::function<void (void)>&& task, std::chrono::nanoseconds interval, size_t n): task_{task}, interval_{interval}, n_{n}, stop_{false} {}

void Timer::run() {
    std::chrono::high_resolution_clock::time_point before;
    std::chrono::nanoseconds function_execution_time, sleep_time, real_sleep_time;
    while (!stop_ && n_ > 0) {
        before = std::chrono::high_resolution_clock::now();
        task_();
        function_execution_time = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - before);
        if (function_execution_time > interval_) {
			std::cerr << "Can't keep up!" << std::endl;
        }
        --n_;
        sleep_time = interval_ - function_execution_time;
        before = std::chrono::high_resolution_clock::now();
        if (interval_ > std::chrono::nanoseconds{5000000}) {
			std::this_thread::sleep_for(sleep_time);
		} else {
			spinsleep::sleep_for(sleep_time);
		}
        real_sleep_time = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - before);
        double diff = ((double) real_sleep_time.count()) / ((double) sleep_time.count());
        if (diff > 1.05 || diff < 0.95) {
			fprintf(stderr, "Timmer is off by %.02f%%!\n", (diff-1)*100);
		}
    }
}

Timer::~Timer() {
	 thread_.join();
}

void Timer::start() {
    thread_ = std::thread{&Timer::run, this};
}

void Timer::stop() {
    if (!stop_) {
        stop_ = true;
        thread_.join();
    }
}
