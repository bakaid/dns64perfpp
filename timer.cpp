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

#include "timer.h"

#include "spin_sleep.hpp"
#include <iostream>
#include <stdio.h> /* GL: needed for setting thread affinity */

Timer::Timer(const std::string &threadName, std::function<void(void)> &&prepare,
             std::function<void(void)> &&task,
             std::chrono::nanoseconds interval, size_t n)
    : thread_name_{threadName}, prepare_{prepare}, task_{task},
      interval_{interval}, n_{n}, stop_{false} {}

void Timer::run() {
  std::chrono::high_resolution_clock::time_point before, starttime;
  std::chrono::nanoseconds interval, function_execution_time, sleep_time,
      full_time;
  size_t n;

  prepare_();

  n = n_;
  starttime = std::chrono::high_resolution_clock::now();
  while (!stop_ && n > 0) {
    before = std::chrono::high_resolution_clock::now();
    interval =
        n_ * interval_ - std::chrono::duration_cast<std::chrono::nanoseconds>(
                             before - starttime);
    if (interval.count() < 0) {
      interval = std::chrono::nanoseconds{0};
    } else {
      interval /= n;
    }
    task_();
    function_execution_time =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now() - before);
#ifdef DEBUG
    if (function_execution_time > interval) {
      std::cerr << "Can't keep up!" << std::endl;
    }
#endif
    --n;
    sleep_time = starttime + (n_ - n) * interval_ -
                 std::chrono::high_resolution_clock::now();
    if (sleep_time.count() > 0) {
#ifdef DEBUG
      before = std::chrono::high_resolution_clock::now();
#endif
      spinsleep::sleep_for(sleep_time);
#ifdef DEBUG
      std::chrono::nanoseconds real_sleep_time =
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              std::chrono::high_resolution_clock::now() - before);
      double diff =
          ((double)real_sleep_time.count()) / ((double)sleep_time.count());
      if (diff > 1.05 || diff < 0.95) {
        fprintf(stderr, "Timer is off by %.02f%%!\n", (diff - 1) * 100);
      }
#endif
    }
  }
  full_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::high_resolution_clock::now() - starttime);
  fprintf(stderr, "Full timer execution took %lu ns, %.02f%% of specified.\n",
          full_time.count(),
          ((double)full_time.count() / (n_ * interval_.count())) * 100);
}

Timer::~Timer() {
  if (!stop_) {
    thread_.join();
  }
}

void Timer::start() {
  thread_ = std::thread{&Timer::run, this};
  pthread_setname_np(thread_.native_handle(), thread_name_.c_str());
  // GL: Set the affinity of the thread
  int thread_id;
  sscanf(thread_name_.c_str(), "Sender %d", &thread_id);  
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(thread_id, &cpuset);
  int rc = pthread_setaffinity_np(thread_.native_handle(), sizeof(cpu_set_t), &cpuset);
  if (rc != 0) 
    fprintf(stderr, "Error calling pthread_setaffinity_np: %d.\n", rc);
  else 
    fprintf(stderr, "Sender thread %d was pinned to CPU core %d.\n", thread_id, thread_id);
}

void Timer::stop() {
  if (!stop_) {
    stop_ = true;
    thread_.join();
  }
}
