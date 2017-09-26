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

#include "dns.h"
#include <algorithm>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>

#include <syslog.h>

DNSLabel::DNSLabel(uint8_t *begin) : begin_{begin} {}

bool DNSLabel::isPointer() const { return (begin_[0] & 0xc0) == 0xc0; }

size_t DNSLabel::offset() const {
  return ntohs(*((uint16_t *)begin_)) & 0x3fff;
}

void DNSLabel::offset(uint16_t off) {
  *((uint16_t *)begin_) = htons(off | 0xc000);
}

size_t DNSLabel::size() const {
  if (isPointer()) {
    return 2;
  } else {
    return begin_[0] + 1;
  }
}

size_t DNSLabel::length() const {
  if (isPointer()) {
    return 0;
  } else {
    return begin_[0];
  }
}

bool operator==(const DNSLabel &lhs, const DNSLabel &rhs) {
  return lhs.begin_ == lhs.begin_;
}

DNSQName::DNSQName(uint8_t *begin, size_t maxlen, DNSPacket &packet)
    : begin_{begin}, packet_{packet} {
  uint8_t *iter = begin;
  while (iter < (begin_ + maxlen)) {
    packet_.get().labels_.push_back(DNSLabel{iter});
    if (iter[0] == 0) {
      break;
    } else if (iter[0] < 64) {
      iter += iter[0] + 1;
    } else if ((iter[0] & 0xc0) == 0xc0) {
      break;
    } else {
      throw std::out_of_range{"Invalid label size"};
    }
  }
  if (size() > maxlen) {
    throw std::out_of_range{"Packet too small"};
  }
}

size_t DNSQName::labelsToString(std::vector<DNSLabel>::iterator first,
                                char *buffer, size_t maxlen) const {
  size_t len = maxlen;
  for (std::vector<DNSLabel>::iterator label = first;
       label != packet_.get().labels_.end(); ++label) {
    if (!label->isPointer()) {
      if (label->length() == 0) {
        break;
      }
      if (len >= (label->length() + 2)) {
        snprintf(buffer, label->length() + 1, "%s", label->begin_ + 1);
        strcat(buffer, ".");
        buffer += label->length() + 1;
        len -= label->length() + 1;
      }
    } else {
      size_t s =
          labelsToString(std::find_if(packet_.get().labels_.begin(),
                                      packet_.get().labels_.end(),
                                      [this, label](const DNSLabel &rhs) {
                                        return (packet_.get().begin_ +
                                                label->offset()) == rhs.begin_;
                                      }),
                         buffer, len);
      buffer += s;
      len -= s;
      break;
    }
  }
  return maxlen - len;
}

size_t DNSQName::toString(char *buffer, size_t maxlen) const {
  return labelsToString(std::find_if(packet_.get().labels_.begin(),
                                     packet_.get().labels_.end(),
                                     [this](const DNSLabel &rhs) {
                                       return rhs.begin_ == begin_;
                                     }),
                        buffer, maxlen);
}

size_t DNSQName::size() const {
  size_t len = 0;
  for (std::vector<DNSLabel>::iterator label = std::find_if(
           packet_.get().labels_.begin(), packet_.get().labels_.end(),
           [this](const DNSLabel &rhs) { return rhs.begin_ == begin_; });
       label != packet_.get().labels_.end(); ++label) {
    len += label->size();
    if (label->isPointer() || label->length() == 0)
      break;
  }
  return len;
}

DNSQuestion::DNSQuestion(uint8_t *begin, size_t maxlen, DNSPacket &packet)
    : begin_{begin}, name_{DNSQName{begin, maxlen, packet}} {
  size_t len = maxlen;

  begin += name_.size();
  len -= name_.size();

  //
  if (len < sizeof(uint16_t))
    throw std::out_of_range{"Packet too small"};
  qtype_ = reinterpret_cast<uint16_t *>(begin);
  begin += sizeof(uint16_t);
  len -= sizeof(uint16_t);

  //
  if (len < sizeof(uint16_t))
    throw std::out_of_range{"Packet too small"};
  qclass_ = reinterpret_cast<uint16_t *>(begin);
  begin += sizeof(uint16_t);
  len -= sizeof(uint16_t);
}
size_t DNSQuestion::size() const {
  return name_.size() + sizeof(uint16_t) + sizeof(uint16_t);
}

uint16_t DNSQuestion::qtype() const { return ntohs(*qtype_); }

void DNSQuestion::qtype(uint16_t q) { *qtype_ = htons(q); }

uint16_t DNSQuestion::qclass() const { return ntohs(*qclass_); }

void DNSQuestion::qclass(uint16_t q) { *qclass_ = htons(q); }

DNSResource::DNSResource(uint8_t *begin, size_t maxlen, DNSPacket &packet)
    : begin_{begin}, name_{DNSQName{begin, maxlen, packet}}, packet_{packet} {
  size_t len = maxlen;

  //
  begin += name_.size();
  len -= name_.size();

  //
  if (len < sizeof(uint16_t))
    throw std::out_of_range{"Packet to small"};
  qtype_ = reinterpret_cast<uint16_t *>(begin);
  begin += sizeof(uint16_t);
  len -= sizeof(uint16_t);

  //
  if (len < sizeof(uint16_t))
    throw std::out_of_range{"Packet too small"};
  qclass_ = reinterpret_cast<uint16_t *>(begin);
  begin += sizeof(uint16_t);
  len -= sizeof(uint16_t);

  //
  if (len < sizeof(uint32_t))
    throw std::out_of_range{"Packet too small"};
  ttl_ = reinterpret_cast<uint32_t *>(begin);
  begin += sizeof(uint32_t);
  len -= sizeof(uint32_t);

  //
  if (len < sizeof(uint16_t))
    throw std::out_of_range{"Packet too small"};
  rdlength_ = reinterpret_cast<uint16_t *>(begin);
  begin += sizeof(uint16_t);
  len -= sizeof(uint16_t);

  //
  if (rdlength() > len)
    throw std::out_of_range{"Packet too small"};
  rdata_ = begin;
}

uint16_t DNSResource::qtype() const { return ntohs(*qtype_); }

void DNSResource::qtype(uint16_t q) { *qtype_ = htons(q); }

uint16_t DNSResource::qclass() const { return ntohs(*qclass_); }

void DNSResource::qclass(uint16_t q) { *qclass_ = htons(q); }

uint32_t DNSResource::ttl() const { return ntohl(*ttl_); }

void DNSResource::ttl(uint32_t ttl) { *ttl_ = htonl(ttl); }

uint16_t DNSResource::rdlength() const { return ntohs(*rdlength_); }

void DNSResource::rdlength(uint16_t r) { *rdlength_ = htons(r); }

uint8_t *DNSResource::rdata() const { return rdata_; }

void DNSResource::rdata(uint8_t *data, size_t newlen) {
  packet_.get().resize(rdata(), rdlength(), newlen);
  rdlength(newlen);
  memcpy(rdata_, data, newlen);
}

size_t DNSResource::rdataToString(char *buffer, size_t maxlen) const {
  buffer[0] = '\0';
  switch (qtype()) {
  case QType::A: {
    struct in_addr addr;
    addr.s_addr = *(reinterpret_cast<uint32_t *>(rdata()));
    inet_ntop(AF_INET, &addr, buffer, maxlen);
    return strlen(buffer) + 1;
  } break;
  case QType::AAAA: {
    struct in6_addr addr6;
    memcpy(addr6.s6_addr, rdata(), sizeof(addr6.s6_addr));
    inet_ntop(AF_INET6, &addr6, buffer, maxlen);
    return strlen(buffer) + 1;
  } break;
  case QType::MX: {
    size_t len = maxlen;
    uint16_t preference = ntohs(*(reinterpret_cast<uint16_t *>(rdata())));
    DNSQName name{rdata() + sizeof(preference), rdlength() - sizeof(preference),
                  packet_};
    size_t s = name.toString(buffer, maxlen);
    buffer += s;
    len -= s;
    snprintf(buffer, len, " %hu", preference);
    return s + strlen(buffer);
  } break;
  case QType::NS: {
    DNSQName name{rdata(), rdlength(), packet_};
    return name.toString(buffer, maxlen);
  } break;
  case QType::CNAME: {
    DNSQName name{rdata(), rdlength(), packet_};
    return name.toString(buffer, maxlen);
  } break;
  case QType::SOA: {
    size_t len = maxlen;
    uint8_t *data = rdata();
    DNSQName mname{data, rdlength(), packet_};
    data += mname.size();
    DNSQName rname{data, rdlength(), packet_};
    data += rname.size();
    uint32_t serial, refresh, retry, expire;
    serial = ntohl(*(reinterpret_cast<uint32_t *>(rdata())));
    data += sizeof(serial);
    refresh = ntohl(*(reinterpret_cast<uint32_t *>(rdata())));
    data += sizeof(refresh);
    retry = ntohl(*(reinterpret_cast<uint32_t *>(rdata())));
    data += sizeof(retry);
    expire = ntohl(*(reinterpret_cast<uint32_t *>(rdata())));
    data += sizeof(expire);

    size_t s = mname.toString(buffer, maxlen);
    buffer += s;
    len -= s;

    snprintf(buffer, len, " ");
    buffer += strlen(" ");
    len -= strlen(" ");

    s = rname.toString(buffer, maxlen);
    buffer += s;
    len -= s;

    snprintf(buffer, len, " ");
    buffer += strlen(" ");
    len -= strlen(" ");

    snprintf(buffer, len, "%u %u %u %u", serial, refresh, retry, expire);
    return 0;
  } break;
  case QType::TXT: {
  } break;
  default:
    break;
  }
  return 0;
}

size_t DNSResource::size() const {
  return name_.size() + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) +
         sizeof(uint16_t) + rdlength();
}

DNSPacket::DNSPacket(uint8_t *begin, size_t len, size_t buflen)
    : begin_{begin}, len_{len}, buflen_{buflen} {

  header_ = reinterpret_cast<DNSHeader *>(begin);
  begin += sizeof(DNSHeader);
  len -= sizeof(DNSHeader);
  if (begin > (begin_ + len_))
    throw std::out_of_range{"Packet too small"};
  //
  for (int i = 0; i < header_->qdcount(); i++) {
    question_.push_back(DNSQuestion{begin, len, *this});
    begin += question_[i].size();
    len -= question_[i].size();
    if (begin > (begin_ + len_))
      throw std::out_of_range{"Packet too small"};
  }
  //
  for (int i = 0; i < header_->ancount(); i++) {
    answer_.push_back(DNSResource{begin, len, *this});
    begin += answer_[i].size();
    len -= answer_[i].size();
    if (begin > (begin_ + len_))
      throw std::out_of_range{"Packet too small"};
  }
  //
  for (int i = 0; i < header_->nscount(); i++) {
    authority_.push_back(DNSResource{begin, len, *this});
    begin += authority_[i].size();
    len -= authority_[i].size();
    if (begin > (begin_ + len_))
      throw std::out_of_range{"Packet too small"};
  }
  //
  for (int i = 0; i < header_->arcount(); i++) {
    additional_.push_back(DNSResource{begin, len, *this});
    begin += additional_[i].size();
    len -= additional_[i].size();
    if (begin > (begin_ + len_))
      throw std::out_of_range{"Packet too small"};
  }
}

DNSPacket::DNSPacket(const DNSPacket &rhs)
    : begin_{rhs.begin_}, len_{rhs.len_}, buflen_{rhs.buflen_},
      header_{rhs.header_}, labels_{rhs.labels_}, question_{rhs.question_},
      answer_{rhs.answer_}, authority_{rhs.authority_}, additional_{
                                                            rhs.additional_} {
  for (auto &question : question_) {
    question.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }

  for (auto &resource : answer_) {
    resource.packet_ = std::reference_wrapper<DNSPacket>{*this};
    resource.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }

  for (auto &resource : authority_) {
    resource.packet_ = std::reference_wrapper<DNSPacket>{*this};
    resource.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }

  for (auto &resource : additional_) {
    resource.packet_ = std::reference_wrapper<DNSPacket>{*this};
    resource.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }
}

DNSPacket::DNSPacket(DNSPacket &&rhs)
    : begin_{rhs.begin_}, len_{rhs.len_}, buflen_{rhs.buflen_},
      header_{rhs.header_}, labels_{rhs.labels_}, question_{rhs.question_},
      answer_{rhs.answer_}, authority_{rhs.authority_}, additional_{
                                                            rhs.additional_} {
  rhs.begin_ = nullptr;
  rhs.len_ = 0;
  rhs.buflen_ = 0;
  rhs.header_ = nullptr;
  for (auto &question : question_) {
    question.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }

  for (auto &resource : answer_) {
    resource.packet_ = std::reference_wrapper<DNSPacket>{*this};
    resource.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }

  for (auto &resource : authority_) {
    resource.packet_ = std::reference_wrapper<DNSPacket>{*this};
    resource.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }

  for (auto &resource : additional_) {
    resource.packet_ = std::reference_wrapper<DNSPacket>{*this};
    resource.name_.packet_ = std::reference_wrapper<DNSPacket>{*this};
  }
}

void DNSPacket::resize(uint8_t *begin, size_t oldsize, size_t newsize) {
  if ((newsize - oldsize) > (buflen_ - len_)) {
    throw std::out_of_range{"Buffer too small"};
  }
  if (begin < begin_ || begin > (begin_ + len_ - oldsize)) {
    throw std::out_of_range{"Illegal resize request"};
  }
  for (auto &question : question_) {
    if (question.begin_ > begin) {
      question.begin_ += (newsize - oldsize);
      question.qtype_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(question.qtype_) + (newsize - oldsize));
      question.qclass_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(question.qclass_) + (newsize - oldsize));
    }
  }
  for (auto &resource : answer_) {
    if (resource.begin_ > begin) {
      resource.begin_ += (newsize - oldsize);
      resource.qtype_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.qtype_) + (newsize - oldsize));
      resource.qclass_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.qclass_) + (newsize - oldsize));
      resource.ttl_ = reinterpret_cast<uint32_t *>(
          reinterpret_cast<uint8_t *>(resource.ttl_) + (newsize - oldsize));
      resource.rdlength_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.rdlength_) +
          (newsize - oldsize));
      resource.rdata_ += (newsize - oldsize);
    }
  }
  for (auto &resource : authority_) {
    if (resource.begin_ > begin) {
      resource.begin_ += (newsize - oldsize);
      resource.qtype_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.qtype_) + (newsize - oldsize));
      resource.qclass_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.qclass_) + (newsize - oldsize));
      resource.ttl_ = reinterpret_cast<uint32_t *>(
          reinterpret_cast<uint8_t *>(resource.ttl_) + (newsize - oldsize));
      resource.rdlength_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.rdlength_) +
          (newsize - oldsize));
      resource.rdata_ += (newsize - oldsize);
    }
  }
  for (auto &resource : additional_) {
    if (resource.begin_ > begin) {
      resource.begin_ += (newsize - oldsize);
      resource.qtype_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.qtype_) + (newsize - oldsize));
      resource.qclass_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.qclass_) + (newsize - oldsize));
      resource.ttl_ = reinterpret_cast<uint32_t *>(
          reinterpret_cast<uint8_t *>(resource.ttl_) + (newsize - oldsize));
      resource.rdlength_ = reinterpret_cast<uint16_t *>(
          reinterpret_cast<uint8_t *>(resource.rdlength_) +
          (newsize - oldsize));
      resource.rdata_ += (newsize - oldsize);
    }
  }
  memmove(begin + newsize, begin + oldsize,
          len_ - ((begin + oldsize) - begin_));
  for (auto &label : labels_) {
    if (label.begin_ > begin) {
      label.begin_ += (newsize - oldsize);
    }
    if (label.isPointer() && label.offset() > (begin - begin_)) {
      label.offset(label.offset() + (newsize - oldsize));
    }
  }
  len_ += (newsize - oldsize);
}
