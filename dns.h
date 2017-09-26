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
 *  @brief Header for DNS protocol related Classes and Enums.
 */

#ifndef DNS_H_INCLUDED_
#define DNS_H_INCLUDED_

#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <map>
#include <netinet/in.h>
#include <stdint.h>
#include <vector>

/**
 * Class to represent a DNS header.
 * Note: this class is not constructed, but casted \a on the raw byte stream.
 * This makes it more efficient.
 */
class DNSHeader {
private:
  uint16_t id_;      /**< The DNS Query identifier */
  uint16_t flags_;   /**< Flags of the DNS packet. */
  uint16_t qdcount_; /**< Question Count. */
  uint16_t ancount_; /**< Answer Resource Count. */
  uint16_t nscount_; /**< Authority Resource Count. */
  uint16_t arcount_; /**< Additional Resource Count. */
public:
  // getters
  inline uint16_t id() const {
    return ntohs(id_);
  } /**< Getter for the DNS Query identifier. */
  inline bool qr() const {
    return (ntohs(flags_) >> 15) & 0x1;
  } /**< Getter for Query(0)/Response(1) flag. */
  inline uint8_t opcode() const {
    return (ntohs(flags_) >> 11) & 0xf;
  } /**< Getter for Opcode. */
  inline bool aa() const {
    return (ntohs(flags_) >> 10) & 0x1;
  } /**< Getter for the Authoritative Answer flag. */
  inline bool tc() const {
    return (ntohs(flags_) >> 9) & 0x1;
  } /**< Getter for the Truncation flag. */
  inline bool rd() const {
    return (ntohs(flags_) >> 8) & 0x1;
  } /**< Getter for the Recursion Desired flag. */
  inline bool ra() const {
    return (ntohs(flags_) >> 7) & 0x1;
  } /**< Getter for the Recursion Avaliable flag. */
  inline uint8_t rcode() const {
    return ntohs(flags_) & 0xf;
  } /**< Getter for the Response Code. */
  inline uint16_t qdcount() const {
    return ntohs(qdcount_);
  } /**< Getter for the Question Count. */
  inline uint16_t ancount() const {
    return ntohs(ancount_);
  } /**< Getter for the Answer Resource Count. */
  inline uint16_t nscount() const {
    return ntohs(nscount_);
  } /**< Getter for the Authority Resource Count. */
  inline uint16_t arcount() const {
    return ntohs(arcount_);
  } /**< Getter for the Additional Resource Count. */
  // setters
  inline void id(uint16_t id_s) {
    id_ = htons(id_s);
  } /**< Setter for the DNS Query identifier. */
  inline void qr(bool qr_s) {
    flags_ &= htons(~(1 << 15));
    flags_ |= htons(((uint16_t)qr_s) << 15);
  } /**< Setter for Query(0)/Response(1) flag. */
  inline void opcode(uint8_t opcode_s) {
    flags_ &= htons(~(0xf << 11));
    flags_ |= htons(((uint16_t)opcode_s) << 11);
  } /**< Setter for Opcode. */
  inline void aa(bool aa_s) {
    flags_ &= htons(~(1 << 10));
    flags_ |= htons(((uint16_t)aa_s) << 10);
  } /**< Setter for the Authoritative Answer flag. */
  inline void tc(bool tc_s) {
    flags_ &= htons(~(1 << 9));
    flags_ |= htons(((uint16_t)tc_s) << 9);
  } /**< Setter for the Truncation flag. */
  inline void rd(bool rd_s) {
    flags_ &= htons(~(1 << 8));
    flags_ |= htons(((uint16_t)rd_s) << 8);
  } /**< Setter for the Recursion Desired flag. */
  inline void ra(bool ra_s) {
    flags_ &= htons(~(1 << 7));
    flags_ |= htons(((uint16_t)ra_s) << 7);
  } /**< Setter for the Recursion Avaliable flag. */
  inline void rcode(uint8_t rcode_s) {
    flags_ &= htons(~(0xf));
    flags_ |= htons((uint16_t)rcode_s);
  } /**< Setter for the Response Code. */
  inline void qdcount(uint16_t qdcount_s) {
    qdcount_ = htons(qdcount_s);
  } /**< Setter for the Question Count. */
  inline void ancount(uint16_t ancount_s) {
    ancount_ = htons(ancount_s);
  } /**< Setter for the Answer Resource Count. */
  inline void nscount(uint16_t nscount_s) {
    nscount_ = htons(nscount_s);
  } /**< Setter for the Authority Resource Count. */
  inline void arcount(uint16_t arcount_s) {
    arcount_ = htons(arcount_s);
  } /**< Setter for the Additional Resource Count. */

  /**
   * Enum for the Opcode.
   */
  enum OpCode { Query = 0, IQuery = 1, Status = 2, Notify = 4, Update = 5 };

  /**
   * Enum for the Result code.
   */
  enum RCODE {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    BadVers = 16,
    BadSig = 16,
    BadKey = 17,
    BadTime = 18,
    BadMode = 19,
    BadName = 20,
    BadAlg = 21,
    BadTrunc = 22
  };
};

/**
 * Enum for the Query Type.
 */
enum QType {
  A = 1,
  NS = 2,
  MD = 3,
  MF = 4,
  CNAME = 5,
  SOA = 6,
  MB = 7,
  MG = 8,
  MR = 9,
  RRNULL = 10,
  WKS = 11,
  PTR = 12,
  HINFO = 13,
  MINFO = 14,
  MX = 15,
  TXT = 16,
  RP = 17,
  AFSDB = 18,
  X25 = 19,
  ISDN = 20,
  RT = 21,
  NSAP = 22,
  NSAP_PTR = 23,
  SIG = 24,
  KEY = 25,
  PX = 26,
  GPOS = 27,
  AAAA = 28,
  LOC = 29,
  NXT = 30,
  EID = 31,
  NIMLOC = 32,
  SRV = 33,
  ATMA = 34,
  NAPTR = 35,
  KX = 36,
  CERT = 37,
  A6 = 38,
  DNAME = 39,
  SINK = 40,
  OPT = 41,
  APL = 42,
  DS = 43,
  SSHFP = 44,
  IPSECKEY = 45,
  RRSIG = 46,
  NSEC = 47,
  DNSKEY = 48,
  DHCID = 49,
  NSEC3 = 50,
  NSEC3PARAM = 51,
  TLSA = 52,
  HIP = 55,
  NINFO = 56,
  RKEY = 57,
  TALINK = 58,
  CDS = 59,
  CDNSKEY = 60,
  OPENPGPKEY = 61,
  CSYNC = 62,
  SPF = 99,
  UINFO = 100,
  UID = 101,
  GID = 102,
  UNSPEC = 103,
  NID = 104,
  L32 = 105,
  L64 = 106,
  LP = 107,
  EUI48 = 108,
  EUI64 = 109,
  TKEY = 249,
  TSIG = 250,
  IXFR = 251,
  AXFR = 252,
  MAILB = 253,
  MAILA = 254,
  ANY = 255,
  URI = 256,
  CAA = 257,
  TA = 32768,
  DLV = 32769
};

/**
 * Map to map QType values to the respective strings for display purposes.
 */
static const std::map<uint16_t, const char *> QTypeStr = {
    {1, "A"},         {2, "NS"},       {3, "MD"},          {4, "MF"},
    {5, "CNAME"},     {6, "SOA"},      {7, "MB"},          {8, "MG"},
    {9, "MR"},        {10, "RRNULL"},  {11, "WKS"},        {12, "PTR"},
    {13, "HINFO"},    {14, "MINFO"},   {15, "MX"},         {16, "TXT"},
    {17, "RP"},       {18, "AFSDB"},   {19, "X25"},        {20, "ISDN"},
    {21, "RT"},       {22, "NSAP"},    {23, "NSAP_PTR"},   {24, "SIG"},
    {25, "KEY"},      {26, "PX"},      {27, "GPOS"},       {28, "AAAA"},
    {29, "LOC"},      {30, "NXT"},     {31, "EID"},        {32, "NIMLOC"},
    {33, "SRV"},      {34, "ATMA"},    {35, "NAPTR"},      {36, "KX"},
    {37, "CERT"},     {38, "A6"},      {39, "DNAME"},      {40, "SINK"},
    {41, "OPT"},      {42, "APL"},     {43, "DS"},         {44, "SSHFP"},
    {45, "IPSECKEY"}, {46, "RRSIG"},   {47, "NSEC"},       {48, "DNSKEY"},
    {49, "DHCID"},    {50, "NSEC3"},   {51, "NSEC3PARAM"}, {52, "TLSA"},
    {55, "HIP"},      {56, "NINFO"},   {57, "RKEY"},       {58, "TALINK"},
    {59, "CDS"},      {60, "CDNSKEY"}, {61, "OPENPGPKEY"}, {62, "CSYNC"},
    {99, "SPF"},      {100, "UINFO"},  {101, "UID"},       {102, "GID"},
    {103, "UNSPEC"},  {104, "NID"},    {105, "L32"},       {106, "L64"},
    {107, "LP"},      {108, "EUI48"},  {109, "EUI64"},     {249, "TKEY"},
    {250, "TSIG"},    {251, "IXFR"},   {252, "AXFR"},      {253, "MAILB"},
    {254, "MAILA"},   {255, "ANY"},    {256, "URI"},       {257, "CAA"},
    {32768, "TA"},    {32769, "DLV"}};

/**
 * Enum for the Query Class.
 */
enum QClass { IN = 1, CH = 3, HS = 4, QCLASS_NONE = 254, QCLASS_ANY = 255 };

/**
 * Map to map QClass values to the respective strings for display purposes.
 */
static const std::map<uint16_t, const char *> QClassStr = {
    {1, "IN"}, {3, "CH"}, {4, "HS"}, {254, "NONE"}, {255, "ANY"}};

struct DNSPacket;

/**
 * Class to represent a DNS label.
 */
struct DNSLabel {
  uint8_t *begin_; /**< Pointer to the beginning of the label. */

  /**
   * Constructor.
   * @param begin pointer to the beginning of the label
   */
  DNSLabel(uint8_t *begin);

  /**
   * Function to find out whether the label is a pointer.
   * @return true if the label is a pointer
   */
  bool isPointer() const;

  /**
   * Returns the offset of the pointer.
   * Warning: this function does NOT check if the label is actually a pointer.
   * @return the offset
   */
  size_t offset() const;

  /**
   * Setter for the offset of the label.
   * @param off the offset
   */
  void offset(uint16_t off);

  /**
   * Returns the actual size of the label in the packet (2 for pointers,
   * length() + 1 for normal labels)
   * @return the size
   */
  size_t size() const;

  /**
   * Returns the length of the label (0 for pointers, the number of characters
   * in the label for normal labels)
   * @return the length
   */
  size_t length() const;
};

/**
 * Comparator function for DNSLabels.
 * @param lhs the first label
 * @param rhs the second label
 * @return true if the labels have the same begin_
 */
bool operator==(const DNSLabel &lhs, const DNSLabel &rhs);

/**
 * Class to represent a DNS Query Name.
 */
struct DNSQName {
  uint8_t *begin_; /**< Pointer to the beginning of the QName. */

  std::reference_wrapper<DNSPacket>
      packet_; /**< Packet to which the QName belongs.*/

  /**
   * Constructor.
   * @param begin pointer to the beginning of the QName
   * @param maxlen the maximum possible length of the QName
   * @param packet packet to which the DNSQName belongs
   */
  DNSQName(uint8_t *begin, size_t maxlen, DNSPacket &packet);

  /**
   * Function to construct a string beginning with the given label,
   * using the global label list constructed during packet processing in
   * the DNSPacket.
   * This function is recursive, and follows the pointers.
   * @param first the iterator to the first label
   * @param buffer the string buffer
   * @param maxlen length of the string buffer
   * @return the number of bytes written to the buffer
   */
  size_t labelsToString(std::vector<DNSLabel>::iterator first, char *buffer,
                        size_t maxlen) const;

  /**
   * Converts the QName to a string using the labelsToString function.
   * @param buffer the string buffer
   * @param maxlen the length of the buffer
   * @return number of bytes written to the buffer
   */
  size_t toString(char *buffer, size_t maxlen) const;

  /**
   * Return the size of the QName in the packet.
   * @return the size
   */
  size_t size() const;
};

/**
 * Class to represent a DNS Question.
 */
struct DNSQuestion {
  uint8_t *begin_;   /**< Pointer to the beginning of the Question. */
  DNSQName name_;    /**< The QName of the Question. */
  uint16_t *qtype_;  /**< The Query Type of the Question. */
  uint16_t *qclass_; /**< The Query Class of the Question. */

  /**
   * Getter for the Query Type.
   * @return Query Type
   */
  uint16_t qtype() const;

  /**
   * Setter for the Query Type.
   * @param q Query Type
   */
  void qtype(uint16_t q);

  /**
   * Getter for the Query Class.
   * @return Query Class
   */
  uint16_t qclass() const;

  /**
   * Setter for the Query Class.
   * @param q Query Class
   */
  void qclass(uint16_t q);

  /**
   * Constructor.
   * @param begin pointer to the beginning of the Question
   * @param maxlen the maximum possible length of the Question
   * @param packet packet to which the DNSQuestion belongs
   */
  DNSQuestion(uint8_t *begin, size_t maxlen, DNSPacket &packet);

  /**
   * Return the size of the Question in the packet.
   * @return the size
   */
  size_t size() const;
};

/**
 * Class to represent a DNS Resource.
 */
struct DNSResource {
  uint8_t *begin_;     /**< Pointer to the beginning of the Question. */
  DNSQName name_;      /**< The QName of the Resource. */
  uint16_t *qtype_;    /**< The Query Type of the Resource. */
  uint16_t *qclass_;   /**< The Query Class of the Resource. */
  uint32_t *ttl_;      /**< The TTL of the Resource. */
  uint16_t *rdlength_; /**< The rdata length of the Resource. */
  uint8_t *rdata_;     /**< The rdata of the Resource. */
  std::reference_wrapper<DNSPacket>
      packet_; /**< Packet to which the Resource belongs.*/

  /**
   * Getter for the Query Type.
   * @return the Query Type
   */
  uint16_t qtype() const;

  /**
   * Setter for the Query Type.
   * @param q the Query Type
   */
  void qtype(uint16_t q);

  /**
   * Getter for the Query Class.
   * @return the Query Class
   */
  uint16_t qclass() const;

  /**
   * Setter for the Query Class.
   * @param q the Query Class
   */
  void qclass(uint16_t q);

  /**
   * Getter for the TTL.
   * @return the TTL
   */
  uint32_t ttl() const;

  /**
   * Setter for the TTL.
   * @param ttl the TTL
   */
  void ttl(uint32_t ttl);

  /**
   * Getter for the rdata length.
   * @return the rdata length
   */
  uint16_t rdlength() const;

  /**
   * Setter for the rdata length.
   * Warning: DO NOT use this alone. The rdata setter automatically changes this
   * field too.
   * @param r the rdata length
   */
  void rdlength(uint16_t r);

  /**
   * Getter for the rdata.
   * @return the rdata
   */
  uint8_t *rdata() const;

  /**
   * Setter for the rdata.
   * Sets the new length, shrinks or expands the packet, sets the Questions,
   * Resources and Labels accordingly and copies the new data.
   * @param data the new data
   * @param newlen the new length
   */
  void rdata(uint8_t *data, size_t newlen);

  /**
   * Constructor.
   * @param begin pointer to the beginning of the Resource
   * @param maxlen the maximum possible length of the Resource
   * @param packet packet to which the Resource belongs
   */
  DNSResource(uint8_t *begin, size_t maxlen, DNSPacket &packet);

  /**
   * Constructs a string from the rdata, if the QType is supported.
   * @param buffer the string buffer
   * @param maxlen the length of the buffer
   * @return number of bytes written to the buffer
   */
  size_t rdataToString(char *buffer, size_t maxlen) const;

  /**
   * Return the size of the Question in the packet.
   * @return the size
   */
  size_t size() const;
};

/**
 * Class to represent a DNS packet.
 */
struct DNSPacket {
  uint8_t *begin_; /**< Pointer to the beginning of the packet. */
  size_t len_;     /**< Length of the packet. */
  size_t buflen_;  /**< Length of the buffer storing the packet. */

  DNSHeader *header_;            /**< The header of the packet. */
  std::vector<DNSLabel> labels_; /**< All the labels contained in the packet. */
  std::vector<DNSQuestion>
      question_; /**< All the Questions contained in the packet. */
  std::vector<DNSResource>
      answer_; /**< All the Answer Resources contained in the packet. */
  std::vector<DNSResource>
      authority_; /**< All the Authority Resources contained in the packet. */
  std::vector<DNSResource>
      additional_; /**< All the Additional Resources contained in the packet. */

  /**
   * Constructor.
   * @param begin pointer to the beginning of the packet
   * @param len the length of the packet
   * @param buflen the length of the buffer storing the packet
   */
  DNSPacket(uint8_t *begin, size_t len, size_t buflen);

  /**
   * Copy constructor.
   * @param rhs DNSPacket to copy from
   */
  DNSPacket(const DNSPacket &rhs);

  /**
   * Move constructor.
   * @param rhs DNSPacket to move from
   */
  DNSPacket(DNSPacket &&rhs);

  /**
   * Function to resize the packet.
   * @param begin the beginning of the field which is being changed
   * @param oldsize the old size of the field
   * @param newsize the new size of the field
   */
  void resize(uint8_t *begin, size_t oldsize, size_t newsize);
};

#endif
