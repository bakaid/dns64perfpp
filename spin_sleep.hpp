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

#ifndef SPIN_SLEEP_H_INCLUDED_
#define SPIN_SLEEP_H_INCLUDED_

#include <chrono>

namespace spinsleep {
template <class Rep, class Period>
void sleep_for(const std::chrono::duration<Rep, Period> &sleep_duration) {
  auto test = std::chrono::high_resolution_clock::now() + sleep_duration;
  while (std::chrono::high_resolution_clock::now() < test)
    ;
}
}; // namespace spinsleep

#endif
