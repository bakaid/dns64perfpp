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

/** @file 
 *  @brief Header for a generic Timer class
 */

#ifndef TIMER_H_INCLUDED
#define TIMER_H_INCLUDED
                                                                                                
#include <thread>                                                                                           
#include <atomic>                                                                                           
#include <chrono>                                                                                           
#include <functional>                                                                                       

/**
 * Class to represent a generic, function execution time corrected timer.
 */                                                                                       
class Timer {
    private:
        std::function<void (void)> task_; /**< std::function polymorphic template to store the task */
        std::chrono::nanoseconds interval_; /**< Timer interval in nanoseconds */
        size_t n_; /**< Number of times to repeat */
        std::thread thread_; /**< The thread on which the timer executes */
        std::atomic<bool> stop_; /**< Atomic variable to stop the timer */
        
        /**
		 * Function to execute on the thread
		 */
        void run();
    public:
		/**
		 * Constructor.
		 * @param task task to execute
		 * @param interval timer interval in nanoseconds
		 * @param n number of time to repeat
		 */
        Timer(std::function<void (void)>&& task, std::chrono::nanoseconds interval, size_t n);
        
        /**
		 * Destructor.
		 */
        ~Timer();
        
        /**
		 * Starts timer.
		 */
        void start();
        
        /**
		 * Stops timer.
		 */
        void stop();
};

#endif
