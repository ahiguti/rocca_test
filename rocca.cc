
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <array>
#include <string>

#ifdef __AES__
#include <immintrin.h>
#endif

#define ALWAYS_INLINE __attribute__((always_inline)) inline

namespace rocca {

namespace detail {

#ifdef __AES__

ALWAYS_INLINE void load_u(__m128i& r, char const *p)
{
  r = _mm_loadu_si128((const __m128i *)p);
}

ALWAYS_INLINE void store_u(__m128i a, char *p)
{
  _mm_storeu_si128((__m128i *)p, a);
}

ALWAYS_INLINE void set_u64x2(__m128i& r, uint64_t h, uint64_t l)
{
  r = _mm_set_epi64x(h, l);
}

ALWAYS_INLINE void aesenc(__m128i& r, __m128i a, __m128i k)
{
  r = _mm_aesenc_si128(a, k);
}

template <typename T> ALWAYS_INLINE void
load_u(T& r, char const *p)
{
  for (unsigned i = 0; i < r.size(); ++i) {
    load_u(r[i], p + i * sizeof(typename T::value_type));
  }
}

template <typename T> ALWAYS_INLINE void
store_u(T a, char *p)
{
  for (unsigned i = 0; i < a.size(); ++i) {
    store_u(a[i], p + i * sizeof(typename T::value_type));
  }
}

template <typename T> ALWAYS_INLINE void
set_u64x2(T& r, uint64_t h, uint64_t l)
{
  for (unsigned i = 0; i < r.size(); ++i) {
    set_u64x2(r[i], h, l);
  }
}

template <typename T> ALWAYS_INLINE void
aesenc(T& r, T a, T k)
{
  for (unsigned i = 0; i < r.size(); ++i) {
    aesenc(r[i], a[i], k[i]);
  }
}

template <typename T> ALWAYS_INLINE T
operator ^(T a, T b)
{
  T r;
  for (unsigned i = 0; i < a.size(); ++i) {
    r[i] = a[i] ^ b[i];
  }
  return r;
}

#endif

#ifdef __VAES__

ALWAYS_INLINE void load_u(__m512i& r, char const *p)
{
  r = _mm512_loadu_si512((const __m512i *)p);
}

ALWAYS_INLINE void store_u(__m512i v, char *p)
{
  _mm512_storeu_si512((__m512i *)p, v);
}

ALWAYS_INLINE void set_u64x2(__m512i& r, uint64_t h, uint64_t l)
{
  r = _mm512_set_epi64(h, l, h, l, h, l, h, l);
}

ALWAYS_INLINE void aesenc(__m512i& r, __m512i a, __m512i k)
{
  r = _mm512_aesenc_epi128(a, k);
}

#endif

////////////////////////////////////////////////////////////////////////

char val2hex(uint8_t v)
{
  if (v < 10) {
    return '0' + v;
  } else if (v < 16) {
    return 'a' + (v - 10);
  }
  throw std::runtime_error("val2hex");
}

uint8_t hex2val(char ch)
{
  if (ch >= '0' && ch <= '9') {
    return uint8_t(ch - '0');
  }
  if (ch >= 'a' && ch <= 'f') {
    return uint8_t(ch - 'a') + 10;
  }
  throw std::runtime_error("hex2val");
}

void hex2bin(const char *s, std::vector<char>& buf_r)
{
  size_t slen = strlen(s);
  if (slen % 2 != 0) {
    throw std::runtime_error("hex2bin");
  }
  size_t len = slen / 2;
  buf_r.resize(len);
  for (size_t i = 0; i < len; ++i) {
    buf_r[i] = (hex2val(uint8_t(s[i * 2])) << 4)
      | hex2val(uint8_t(s[i * 2 + 1]));
  }
}

template <typename Tbuf> std::string bin2hex(Tbuf const& buf)
{
  std::string s(buf.size() * 2, 0);
  for (size_t i = 0; i < buf.size(); ++i) {
    s[i * 2] = val2hex(uint8_t(buf[i]) >> 4);
    s[i * 2 + 1] = val2hex(uint8_t(buf[i]) & 0x0f);
  }
  return s;
}

template <typename T> std::string tohex(T v)
{
  std::vector<char> buf(sizeof(T));
  store_u(v, &buf[0]);
  return bin2hex(buf);
}

////////////////////////////////////////////////////////////////////////

template <typename T> ALWAYS_INLINE void
rocca_round_update(T& s0, T& s1, T& s2, T& s3, T& s4, T& s5, T& s6, T& s7,
  T v0, T v1)
{
  T s7t = s7;
  T s6t = s6;
  s7 = s0 ^ s6;
  aesenc(s6, s5, s4);
  aesenc(s5, s4, s3);
  s4 = s3 ^ v1;
  aesenc(s3, s2, s1);
  s2 = s1 ^ s6t;
  aesenc(s1, s0, s7t);
  s0 = s7t ^ v0;
}

template <typename T> ALWAYS_INLINE void
rocca_initialize(T& s0, T& s1, T& s2, T& s3, T& s4, T& s5,
  T& s6, T& s7, T nonce, T key0, T key1)
{
  T z0, z1;
  set_u64x2(z0, 0x428a2f98d728ae22llu, 0x7137449123ef65cdllu);
  set_u64x2(z1, 0xb5c0fbcfec4d3b2fllu, 0xe9b5dba58189dbbcllu);
  s0 = key1;
  s1 = nonce;
  s2 = z0;
  s3 = z1;
  s4 = nonce ^ key1;
  s5 = s5 ^ s5;
  s6 = key0;
  s7 = s7 ^ s7;
  for (size_t i = 0; i < 20; ++i) {
    rocca_round_update(s0, s1, s2, s3, s4, s5, s6, s7, z0, z1);
  }
}

template <typename T, unsigned I, unsigned N> ALWAYS_INLINE void
rocca_encrypt_block(T& s0, T& s1, T& s2, T& s3, T& s4, T& s5,
  T& s6, T& s7, char const *plain, char *cipher)
{
  T m0, m1;
  load_u(m0, plain + sizeof(T) * I);
  load_u(m1, plain + sizeof(T) * (N + I));
  T c0, c1;
  aesenc(c0, s1, s5);
  c0 = c0 ^ m0;
  aesenc(c1, s0 ^ s4, s2);
  c1 = c1 ^ m1;
  store_u(c0, cipher + sizeof(T) * I);
  store_u(c1, cipher + sizeof(T) * (N + I));
  #ifdef DEBUG
  printf("encblk m0,m1,s0 %s %s %s\n", tohex(m0).c_str(),
    tohex(m1).c_str(), tohex(s0).c_str());
  #endif
  rocca_round_update(s0, s1, s2, s3, s4, s5, s6, s7, m0, m1);
}

template <typename T, unsigned I, unsigned N> ALWAYS_INLINE void
rocca_decrypt_block(T& s0, T& s1, T& s2, T& s3, T& s4, T& s5, T& s6, T& s7,
  char const *cipher, char *plain)
{
  T c0, c1;
  load_u(c0, cipher + sizeof(T) * I);
  load_u(c1, cipher + sizeof(T) * (N + I));
  T m0, m1;
  aesenc(m0, s1, s5);
  m0 = m0 ^ c0;
  aesenc(m1, s0 ^ s4, s2);
  m1 = m1 ^ c1;
  store_u(m0, plain + sizeof(T) * I);
  store_u(m1, plain + sizeof(T) * (N + I));
  #ifdef DEBUG
  printf("deccblk m0,m1,s0 %s %s %s\n", tohex(m0).c_str(),
    tohex(m1).c_str(), tohex(s0).c_str());
  #endif
  rocca_round_update(s0, s1, s2, s3, s4, s5, s6, s7, m0, m1);
}

template <typename T, unsigned I, unsigned N> ALWAYS_INLINE void
rocca_decrypt_block_tail(T& s0, T& s1, T& s2, T& s3, T& s4,
  T& s5, T& s6, T& s7, char const *cipher, char *plain, size_t tail_len)
{
  T c0, c1;
  load_u(c0, cipher + sizeof(T) * I);
  load_u(c1, cipher + sizeof(T) * (N + I));
  T m0, m1;
  aesenc(m0, s1, s5);
  m0 = m0 ^ c0;
  aesenc(m1, s0 ^ s4, s2);
  m1 = m1 ^ c1;
  store_u(m0, plain + sizeof(T) * I);
  store_u(m1, plain + sizeof(T) * (N + I));
  memset(plain + tail_len, 0, sizeof(T) * N * 2 - tail_len);
  load_u(m0, plain + sizeof(T) * I);
  load_u(m1, plain + sizeof(T) * (N + I));
  #ifdef DEBUG
  printf("deccblk m0,m1,s0 %s %s %s\n", tohex(m0).c_str(),
    tohex(m1).c_str(), tohex(s0).c_str());
  #endif
  rocca_round_update(s0, s1, s2, s3, s4, s5, s6, s7, m0, m1);
}

template <typename T, unsigned I, unsigned N> ALWAYS_INLINE void
rocca_process_assoc_data(T& s0, T& s1, T& s2, T& s3, T& s4,
  T& s5, T& s6, T& s7, char const *ad, size_t len)
{
  size_t constexpr blksz = sizeof(T) * N * 2;
  size_t len_tr = len / blksz * blksz;
  for (size_t i = 0; i < len_tr; i += blksz) {
    T v0, v1;
    load_u(v0, ad + i + sizeof(T) * I);
    load_u(v1, ad + i + sizeof(T) * (N + I));
    rocca_round_update(s0, s1, s2, s3, s4, s5, s6, s7, v0, v1);
  }
  if (len_tr != len) {
    size_t const len_rem = len - len_tr;
    size_t constexpr tsz = sizeof(T);
    size_t constexpr o0 = tsz * I;
    size_t constexpr o1 = tsz * (N + I);
    char c[tsz * 2] = { }; // TODO: aligned
    size_t tail0 = 0;
    size_t tail1 = 0;
    if (o0 < len_rem) {
      tail0 = std::min(len_rem - o0, tsz);
      memcpy(c, ad + len_tr + o0, tail0);
    }
    if (o1 < len_rem) {
      tail1 = std::min(len_rem - o1, tsz);
      memcpy(c + tsz, ad + len_tr + o1, tail1);
    }
    T v0, v1;
    load_u(v0, c);
    load_u(v1, c + tsz);
    rocca_round_update(s0, s1, s2, s3, s4, s5, s6, s7, v0, v1);
  }
}

template <typename T, unsigned I, unsigned N> ALWAYS_INLINE void
rocca_encrypt_blocks(T& s0, T& s1, T& s2, T& s3, T& s4, T& s5,
  T& s6, T& s7, char const *plain, size_t len, char *cipher)
{
  size_t constexpr blksz = sizeof(T) * N * 2;
  size_t len_tr = len / blksz * blksz;
  for (size_t i = 0; i < len_tr; i += blksz) {
    rocca_encrypt_block<T, I, N>(s0, s1, s2, s3, s4, s5, s6, s7, plain + i,
      cipher + i);
  }
  if (len_tr != len) {
    size_t const len_rem = len - len_tr;
    size_t constexpr tsz = sizeof(T);
    size_t constexpr o0 = tsz * I;
    size_t constexpr o1 = tsz * (N + I);
    char c[tsz * 2] = { }; // TODO: aligned
    size_t tail0 = 0;
    size_t tail1 = 0;
    if (o0 < len_rem) {
      tail0 = std::min(len_rem - o0, tsz);
      memcpy(c, plain + len_tr + o0, tail0);
    }
    if (o1 < len_rem) {
      tail1 = std::min(len_rem - o1, tsz);
      memcpy(c + tsz, plain + len_tr + o1, tail1);
    }
    rocca_encrypt_block<T, 0, 1>(s0, s1, s2, s3, s4, s5, s6, s7, c, c);
    if (o0 < len_rem) {
      memcpy(cipher + len_tr + o0, c, tail0);
    }
    if (o1 < len_rem) {
      memcpy(cipher + len_tr + o1, c + tsz, tail1);
    }
  }
}

template <typename T, unsigned I, unsigned N> ALWAYS_INLINE void
rocca_decrypt_blocks(T& s0, T& s1, T& s2, T& s3, T& s4, T& s5,
  T& s6, T& s7, char const *cipher, size_t len, char *plain)
{
  size_t constexpr blksz = sizeof(T) * N * 2;
  size_t len_tr = len / blksz * blksz;
  for (size_t i = 0; i < len_tr; i += blksz) {
    rocca_decrypt_block<T, I, N>(s0, s1, s2, s3, s4, s5, s6, s7, cipher + i,
      plain + i);
  }
  if (len_tr != len) {
    size_t const len_rem = len - len_tr;
    size_t constexpr tsz = sizeof(T);
    size_t constexpr o0 = tsz * I;
    size_t constexpr o1 = tsz * (N + I);
    char c[tsz * 2] = { }; // TODO: aligned
    size_t tail0 = 0;
    size_t tail1 = 0;
    if (o0 < len_rem) {
      tail0 = std::min(len_rem - o0, tsz);
      memcpy(c, cipher + len_tr + o0, tail0);
    }
    if (o1 < len_rem) {
      tail1 = std::min(len_rem - o1, tsz);
      memcpy(c + tsz, cipher + len_tr + o1, tail1);
    }
    rocca_decrypt_block_tail<T, 0, 1>(s0, s1, s2, s3, s4, s5, s6, s7, c, c,
      tail0 + tail1);
    if (o0 < len_rem) {
      memcpy(plain + len_tr + o0, c, tail0);
    }
    if (o1 < len_rem) {
      memcpy(plain + len_tr + o1, c + tsz, tail1);
    }
  }
}

template <typename T> ALWAYS_INLINE T
rocca_finalize(T& s0, T& s1, T& s2, T& s3, T& s4, T& s5,
  T& s6, T& s7, size_t ad_len, size_t cipher_len)
{
  T adv, ev;
  set_u64x2(adv, 0, ad_len << 3);  // TODO: 128bit shift
  set_u64x2(ev, 0, cipher_len << 3);
  for (size_t i = 0; i < 20; ++i) {
    rocca_round_update(s0, s1, s2, s3, s4, s5, s6, s7, adv, ev);
  }
  return s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6 ^ s7;
}

}; // namespace rocca::detail

template <typename T, unsigned I, unsigned N> T
rocca_encrypt(T nonce, T key0, T key1, char const *ad,
  size_t ad_len, char const *plain, size_t plain_len, char *cipher)
{
  using namespace rocca::detail;
  T s0, s1, s2, s3, s4, s5, s6, s7;
  rocca_initialize(s0, s1, s2, s3, s4, s5, s6, s7, nonce, key0, key1);
  rocca_process_assoc_data<T, I, N>(s0, s1, s2, s3, s4, s5, s6, s7, ad, ad_len);
  rocca_encrypt_blocks<T, I, N>(s0, s1, s2, s3, s4, s5, s6, s7, plain,
    plain_len, cipher);
  return rocca_finalize(s0, s1, s2, s3, s4, s5, s6, s7, ad_len, plain_len);
}

template <typename T, unsigned I, unsigned N> T
rocca_decrypt(T nonce, T key0, T key1, char const *ad,
  size_t ad_len, char const *cipher, size_t cipher_len, char *plain)
{
  using namespace rocca::detail;
  T s0, s1, s2, s3, s4, s5, s6, s7;
  rocca_initialize(s0, s1, s2, s3, s4, s5, s6, s7, nonce, key0, key1);
  rocca_process_assoc_data<T, I, N>(s0, s1, s2, s3, s4, s5, s6, s7, ad, ad_len);
  rocca_decrypt_blocks<T, I, N>(s0, s1, s2, s3, s4, s5, s6, s7, cipher,
    cipher_len, plain);
  return rocca_finalize(s0, s1, s2, s3, s4, s5, s6, s7, ad_len, cipher_len);
}

namespace detail {

template <typename T, unsigned I, unsigned N>
struct rocca_reordered_loop;

template <typename T, unsigned N>
struct rocca_reordered_loop<T, 0, N> {
  typedef std::array<T, N> tarr;
  static void encrypt(tarr nonce, tarr key0, tarr key1, char const *ad,
    size_t ad_len, char const *plain, size_t plain_len, char *cipher,
    tarr& r) {
    r[0] = rocca_encrypt<T, 0, N>(nonce[0], key0[0], key1[0], ad, ad_len,
      plain, plain_len, cipher);
  }
  static void decrypt(tarr nonce, tarr key0, tarr key1, char const *ad,
    size_t ad_len, char const *cipher, size_t cipher_len, char *plain,
    tarr& r) {
    r[0] = rocca_decrypt<T, 0, N>(nonce[0], key0[0], key1[0], ad, ad_len,
      cipher, cipher_len, plain);
  }
};

template <typename T, unsigned I, unsigned N>
struct rocca_reordered_loop {
  typedef std::array<T, N> tarr;
  static void encrypt(tarr nonce, tarr key0, tarr key1, char const *ad,
    size_t ad_len, char const *plain, size_t plain_len, char *cipher,
    tarr& r) {
    rocca_reordered_loop<T, I - 1, N>::encrypt(nonce, key0, key1, ad, ad_len,
      plain, plain_len, cipher, r);
    r[I] = rocca_encrypt<T, I, N>(nonce[I], key0[I], key1[I], ad, ad_len,
      plain, plain_len, cipher);
  }
  static void decrypt(tarr nonce, tarr key0, tarr key1, char const *ad,
    size_t ad_len, char const *cipher, size_t cipher_len, char *plain,
    tarr& r) {
    rocca_reordered_loop<T, I - 1, N>::decrypt(nonce, key0, key1, ad, ad_len,
      cipher, cipher_len, plain, r);
    r[I] = rocca_decrypt<T, I, N>(nonce[I], key0[I], key1[I], ad, ad_len,
      cipher, cipher_len, plain);
  }
};

}; // namespace rocca::detail

template <typename Tarr> Tarr
rocca_encrypt_reordered(Tarr nonce, Tarr key0, Tarr key1, const char *ad,
  size_t ad_len, char const *plain, size_t plain_len, char *cipher)
{
  using namespace rocca::detail;
  typedef typename Tarr::value_type te;
  constexpr size_t n = nonce.size();
  Tarr r;
  rocca_reordered_loop<te, n - 1, n>::encrypt(nonce, key0, key1, ad, ad_len,
    plain, plain_len, cipher, r);
  return r;
}

template <typename Tarr> Tarr
rocca_decrypt_reordered(Tarr nonce, Tarr key0, Tarr key1, const char *ad,
  size_t ad_len, char const *cipher, size_t cipher_len, char *plain)
{
  using namespace rocca::detail;
  typedef typename Tarr::value_type te;
  constexpr size_t n = nonce.size();
  Tarr r;
  rocca_reordered_loop<te, n - 1, n>::decrypt(nonce, key0, key1, ad, ad_len,
    cipher, cipher_len, plain, r);
  return r;
}

}; // namespace rocca

////////////////////////////////////////////////////////////////////////

template <typename T> void
verify_one(bool verbose, const char *key, const char *nonce,
  const char *ad, const char *text, const char *cipher, const char *tag)
{
  using namespace rocca;
  using namespace rocca::detail;
  size_t constexpr tsz = sizeof(T);
  if (verbose) {
    printf("key=%s\n", key);
    printf("nonce=%s\n", nonce);
    printf("ad=%s\n", ad);
    printf("text=%s\n", text);
    if (cipher != nullptr) {
      printf("cipher=%s\n", cipher);
    }
    if (tag != nullptr) {
      printf("tag=%s\n", tag);
    }
  }
  std::vector<char> buf_key, buf_nonce, buf_ad, buf_text, buf_cipher,
    buf_tag, buf_text_comp, buf_cipher_comp, buf_tag_enc_comp,
    buf_tag_dec_comp;
  hex2bin(key, buf_key);
  hex2bin(nonce, buf_nonce);
  hex2bin(ad, buf_ad);
  hex2bin(text, buf_text);
  if (cipher != nullptr) {
    hex2bin(cipher, buf_cipher);
  }
  if (tag != nullptr) {
    hex2bin(tag, buf_tag);
  }
  if (buf_key.size() != tsz * 2) {
    throw std::runtime_error("verify key size");
  }
  if (buf_nonce.size() != tsz) {
    throw std::runtime_error("verify nonce size");
  }
  if (!buf_tag.empty() && buf_tag.size() != tsz) {
    throw std::runtime_error("verify tag size");
  }
  buf_text_comp.resize(buf_text.size());
  buf_cipher_comp.resize(buf_text.size());
  buf_tag_enc_comp.resize(tsz);
  buf_tag_dec_comp.resize(tsz);
  {
    T key0, key1;
    load_u(key0, buf_key.data());
    load_u(key1, buf_key.data() + tsz);
    T nonce;
    load_u(nonce, buf_nonce.data());
    {
      T tag = rocca_encrypt<T, 0, 1>(nonce, key0, key1, buf_ad.data(),
        buf_ad.size(), buf_text.data(), buf_text.size(),
        buf_cipher_comp.data());
      store_u(tag, buf_tag_enc_comp.data());
    }
    {
      T tag = rocca_decrypt<T, 0, 1>(nonce, key0, key1, buf_ad.data(),
        buf_ad.size(), buf_cipher_comp.data(), buf_cipher_comp.size(),
        buf_text_comp.data());
      store_u(tag, buf_tag_dec_comp.data());
    }
  }
  if (verbose) {
    printf("cipher_comp=%s\n", bin2hex(buf_cipher_comp).c_str());
    printf("text_comp=%s\n", bin2hex(buf_text_comp).c_str());
    printf("tag_enc_comp=%s\n", bin2hex(buf_tag_enc_comp).c_str());
    printf("tag_dec_comp=%s\n", bin2hex(buf_tag_dec_comp).c_str());
  }
  if (cipher != nullptr && buf_cipher != buf_cipher_comp) {
    throw std::runtime_error("verify cipher");
  }
  if (tag != nullptr && buf_tag != buf_tag_enc_comp) {
    throw std::runtime_error("verify enc tag");
  }
  if (buf_text != buf_text_comp) {
    throw std::runtime_error("verify text");
  }
  if (tag != nullptr && buf_tag != buf_tag_dec_comp) {
    throw std::runtime_error("verify dec tag");
  }
  if (buf_tag_enc_comp != buf_tag_dec_comp) {
    throw std::runtime_error("verify enc dec tag");
  }
}

template <typename T, typename Enc, typename Dec> void
test_perf(Enc enc, Dec dec, bool verbose, bool verify_decrypt,
  const char *key, const char *nonce, size_t adlen, size_t textlen, size_t loop)
{
  using namespace rocca;
  using namespace rocca::detail;
  size_t constexpr tsz = sizeof(T);
  if (verbose) {
    printf("key=%s\n", key);
    printf("nonce=%s\n", nonce);
  }
  std::vector<char> buf_key, buf_nonce, buf_ad, buf_text, buf_cipher,
    buf_tag, buf_text_comp, buf_cipher_comp, buf_tag_enc_comp,
    buf_tag_dec_comp;
  hex2bin(key, buf_key);
  hex2bin(nonce, buf_nonce);
  for (size_t i = 0; i < adlen; ++i) {
    buf_ad.push_back(i & 0xff);
  }
  for (size_t i = 0; i < textlen; ++i) {
    buf_text.push_back(i & 0xff);
  }
  if (buf_key.size() != tsz * 2) {
    throw std::runtime_error("verify key size");
  }
  if (buf_nonce.size() != tsz) {
    throw std::runtime_error("verify nonce size");
  }
  buf_tag.resize(tsz);
  buf_text_comp.resize(buf_text.size());
  buf_cipher_comp.resize(buf_text.size());
  buf_tag_enc_comp.resize(tsz);
  buf_tag_dec_comp.resize(tsz);
  {
    // printf("test_perf begin\n");
    T key0, key1;
    load_u(key0, buf_key.data());
    load_u(key1, buf_key.data() + tsz);
    T nonce;
    load_u(nonce, buf_nonce.data());
    auto t0 = std::chrono::system_clock::now();
    for (size_t i = 0; i < loop; ++i) {
      T ndiff;
      set_u64x2(ndiff, 0, i);
      nonce = nonce ^ ndiff;
      T tag = enc(nonce, key0, key1, buf_ad.data(),
        buf_ad.size(), buf_text.data(), buf_text.size(),
        buf_cipher_comp.data());
      store_u(tag, buf_tag_enc_comp.data());
      if (verify_decrypt) {
        T tag = dec(nonce, key0, key1, buf_ad.data(),
          buf_ad.size(), buf_cipher_comp.data(), buf_cipher_comp.size(),
          buf_text_comp.data());
        store_u(tag, buf_tag_dec_comp.data());
        if (buf_text != buf_text_comp) {
          throw std::runtime_error("verify text");
        }
        if (buf_tag_enc_comp != buf_tag_dec_comp) {
          throw std::runtime_error("verify enc dec tag");
        }
      }
    }
    auto t1 = std::chrono::system_clock::now();
    double elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      t1 - t0).count();
    elapsed /= 1000000000.0;
    double bps = double(loop) * double(adlen + textlen) * 8.0 / elapsed;
    printf("test_perf(%s) T=%zu adlen=%zu textlen=%zu loop=%zu %f (%f gbps)\n",
      (verify_decrypt ? "enc+dec+verify" : "enc"), sizeof(T), adlen, textlen,
      loop, elapsed, bps / 1000000000.0);
  }
}

void verify_test_vector()
{
  using namespace rocca;
  using namespace rocca::detail;
  #ifdef __AES__
  verify_one<__m128i>(true,
    // key
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000",
    // nonce
    "0000000000000000" "0000000000000000",
    // ad
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000",
    // text
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000",
    // cipher
    "15892f8555ad2db4" "749b90926571c4b8"
    "c28b434f277793c5" "3833cb6e41a85529"
    "1784a2c7fe374b34" "d875fdcbe84f5b88"
    "bf3f386f2218f046" "a84318565026d755",
    // tag
    "cc728c8baedd36f1" "4cf8938e9e0719bf");
  verify_one<__m128i>(true,
    // key
    "0101010101010101" "0101010101010101"
    "0101010101010101" "0101010101010101",
    // nonce
    "0101010101010101" "0101010101010101",
    // ad
    "0101010101010101" "0101010101010101"
    "0101010101010101" "0101010101010101",
    // text
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000",
    // cipher
    "f931a8730b2e8a3a" "f341c83a29c30525"
    "325c170326c29d91" "b24d714fecf385fd"
    "88e650ef2e2c02b3" "7b19e70bb93ff82a"
    "a96d50c9fdf05343" "f6e36b66ee7bda69",
    // tag
    "bad0a53616599bfd" "b553788fdaabad78");
  verify_one<__m128i>(true,
    // key
    "0123456789abcdef" "0123456789abcdef"
    "0123456789abcdef" "0123456789abcdef",
    // nonce
    "0123456789abcdef" "0123456789abcdef",
    // ad
    "0123456789abcdef" "0123456789abcdef"
    "0123456789abcdef" "0123456789abcdef",
    // text
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000"
    "0000000000000000" "0000000000000000",
    // cipher
    "265b7e314141fd14" "8235a5305b217ab2"
    "91a2a7aeff91efd3" "ac603b28e0576109"
    "723422ef3f553b0b" "07ce7263f63502a0"
    "0591de648f3ee3b0" "5441d8313b138b5a",
    // tag
    "6672534a8b57c287" "bcf56823cd1cdb5a");
  verify_one<__m128i>(true,
    // key
    "1111111111111111" "1111111111111111"
    "2222222222222222" "2222222222222222",
    // nonce
    "4444444444444444" "4444444444444444",
    // ad
    "8081828384858687" "88898a8b8c8d8e8f9091",
    // text
    "0001020304050607" "08090a0b0c0d0e0f"
    "1011121314151617" "18191a1b1c1d1e1f"
    "2021222324252627" "28292a2b2c2d2e2f"
    "3031323334353637" "38393a3b3c3d3e3f",
    // cipher
    "348b6f6efad807d2" "46ebf345e730d83e"
    "5963bd6d29eedc49" "a13540545ae232a7"
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09",
    // tag
    "a9f2069456559de3" "e69d233e154ba05e");
  #endif
}

void verify_misc()
{
  using namespace rocca;
  using namespace rocca::detail;
  size_t constexpr maxlen = 10000;
  for (size_t len = 0; len < maxlen; ++len) {
    std::string s;
    for (size_t i = 0; i < len * 2; ++i) {
      s.push_back(val2hex(i & 0x0f));
    }
    #ifdef __AES__
    verify_one<__m128i>(false,
      // key
      "034ed4ef198a1eb1" "f8b116a1760354b7"
      "7260d6f2cca46efc" "adfc4765fffe9f09",
      // nonce
      "3031323334353637" "38393a3b3c3d3e3f",
      // ad
      "",
      // text
      s.c_str(),
      // cipher
      nullptr,
      // tag
      nullptr);
    #endif
    #ifdef __VAES__
    verify_one<__m512i>(false,
      // key
      "034ed4ef198a1eb1" "f8b116a1760354b7"
      "7260d6f2cca46efc" "adfc4765fffe9f09"
      "034ed4ef198a1eb1" "f8b116a1760354b7"
      "7260d6f2cca46efc" "adfc4765fffe9f09"
      "034ed4ef198a1eb1" "f8b116a1760354b7"
      "7260d6f2cca46efc" "adfc4765fffe9f09"
      "034ed4ef198a1eb1" "f8b116a1760354b7"
      "7260d6f2cca46efc" "adfc4765fffe9f09",
      // nonce
      "3031323334353637" "38393a3b3c3d3e3f"
      "3031323334353637" "38393a3b3c3d3e3f"
      "3031323334353637" "38393a3b3c3d3e3f"
      "3031323334353637" "38393a3b3c3d3e3f",
      // ad
      "",
      // text
      s.c_str(),
      // cipher
      nullptr,
      // tag
      nullptr);
    #endif
  }
  printf("verify maxlen=%zu\n", maxlen);
}

template <typename T> std::pair<std::string, std::string>
test_interleave_1(const char *key512, const char *nonce512, const char *text,
  size_t textlen)
{
  using namespace rocca;
  using namespace rocca::detail;
  std::string cipher, tagstr;
  constexpr size_t tsz = sizeof(T);
  T key0, key1;
  load_u(key0, key512);
  load_u(key1, key512 + tsz);
  T nonce;
  load_u(nonce, nonce512);
  cipher.resize(textlen);
  T tag = rocca_encrypt<T, 0, 1>(nonce, key0, key1, nullptr, 0, text, textlen,
    &cipher[0]);
  tagstr.resize(tsz);
  store_u(tag, &tagstr[0]);
  return std::make_pair(cipher, tagstr);
}

template <typename T> std::pair<std::string, std::string>
test_interleave_4(const char *key512, const char *nonce512, const char *text,
  size_t textlen)
{
  using namespace rocca;
  using namespace rocca::detail;
  std::string cipher, tagstr;
  cipher.resize(textlen);
  for (unsigned i = 0; i < 4; ++i) {
    std::string tstr;
    constexpr size_t tsz = sizeof(T);
    T key0, key1;
    load_u(key0, key512 + tsz * i);
    load_u(key1, key512 + tsz * (4 + i));
    T nonce;
    load_u(nonce, nonce512 + tsz * i);
    T tag;
    switch (i) {
    case 0: tag = rocca_encrypt<T, 0, 4>(nonce, key0, key1, nullptr, 0, text,
      textlen, &cipher[0]);
      break;
    case 1: tag = rocca_encrypt<T, 1, 4>(nonce, key0, key1, nullptr, 0, text,
      textlen, &cipher[0]);
      break;
    case 2: tag = rocca_encrypt<T, 2, 4>(nonce, key0, key1, nullptr, 0, text,
      textlen, &cipher[0]);
      break;
    case 3: tag = rocca_encrypt<T, 3, 4>(nonce, key0, key1, nullptr, 0, text,
      textlen, &cipher[0]);
      break;
    }
    tstr.resize(tsz);
    store_u(tag, &tstr[0]);
    tagstr += tstr;
  }
  return std::make_pair(cipher, tagstr);
}

void test_interleave()
{
  using namespace rocca;
  using namespace rocca::detail;
  bool failed = false;
  const char *key512s =
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09"
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09"
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09"
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09";
  const char *nonce512s =
    "3031323334353637" "38393a3b3c3d3e3f"
    "3031323334353637" "38393a3b3c3d3e3f"
    "3031323334353637" "38393a3b3c3d3e3f"
    "3031323334353637" "38393a3b3c3d3e3f";
  std::vector<char> key512, nonce512;
  hex2bin(key512s, key512);
  hex2bin(nonce512s, nonce512);
  size_t constexpr maxlen = 10000;
  for (size_t len = 0; len < maxlen; ++len) {
    std::vector<char> text, cipher;
    for (size_t i = 0; i < len; ++i) {
      text.push_back(i & 0xff);
    }
    auto r0 = test_interleave_1<std::array<__m128i, 4>>(key512.data(),
      nonce512.data(), text.data(), text.size());
    auto r1 = test_interleave_4<__m128i>(key512.data(), nonce512.data(),
      text.data(), text.size());
    if (r0 != r1) {
      printf("m512     : %s %s\n", bin2hex(r0.first).c_str(),
        bin2hex(r0.second).c_str());
      printf("m128i arr: %s %s\n", bin2hex(r1.first).c_str(),
        bin2hex(r1.second).c_str());
      failed = true;
    }
    #ifdef __VAES__
    auto r2 = test_interleave_1<__m512i>(key512.data(), nonce512.data(),
      text.data(), text.size());
    if (r0 != r2) {
      printf("m512     : %s %s\n", bin2hex(r0.first).c_str(),
        bin2hex(r0.second).c_str());
      printf("m128i il : %s %s\n", bin2hex(r2.first).c_str(),
        bin2hex(r2.second).c_str());
      failed = true;
    }
    #endif
  }
  if (failed) {
    throw std::runtime_error("test_interleave");
  }
  printf("test_interleave done\n");
}

void test_perf_len()
{
  using namespace rocca;
  using namespace rocca::detail;
  const char *key128 =
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09";
  const char *nonce128 =
    "3031323334353637" "38393a3b3c3d3e3f";
  const char *key512 =
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09"
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09"
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09"
    "034ed4ef198a1eb1" "f8b116a1760354b7"
    "7260d6f2cca46efc" "adfc4765fffe9f09";
  const char *nonce512 =
    "3031323334353637" "38393a3b3c3d3e3f"
    "3031323334353637" "38393a3b3c3d3e3f"
    "3031323334353637" "38393a3b3c3d3e3f"
    "3031323334353637" "38393a3b3c3d3e3f";
  for (size_t len = 1; len < 1024 * 1024 * 256; len *= 2) {
    size_t loop = 1000000000 / (len + 1000);
    #ifdef __AES__
    printf("m128i\n");
    test_perf<__m128i>(
      &rocca_encrypt<__m128i, 0, 1>,
      &rocca_decrypt<__m128i, 0, 1>,
      false, false, key128, nonce128, 0, len, loop);
    test_perf<__m128i>(
      &rocca_encrypt<__m128i, 0, 1>,
      &rocca_decrypt<__m128i, 0, 1>,
      false, true, key128, nonce128, 0, len, loop);
    printf("m128i x4\n");
    test_perf<std::array<__m128i, 4>>(
      &rocca_encrypt<std::array<__m128i, 4>, 0, 1>,
      &rocca_decrypt<std::array<__m128i, 4>, 0, 1>,
      false, false, key512, nonce512, 0, len, loop);
    test_perf<std::array<__m128i, 4>>(
      &rocca_encrypt<std::array<__m128i, 4>, 0, 1>,
      &rocca_decrypt<std::array<__m128i, 4>, 0, 1>,
      false, true, key512, nonce512, 0, len, loop);
    printf("m128i x4 reordered\n");
    test_perf<std::array<__m128i, 4>>(
      &rocca_encrypt_reordered<std::array<__m128i, 4>>,
      &rocca_decrypt_reordered<std::array<__m128i, 4>>,
      false, false, key512, nonce512, 0, len, loop);
    test_perf<std::array<__m128i, 4>>(
      &rocca_encrypt_reordered<std::array<__m128i, 4>>,
      &rocca_decrypt_reordered<std::array<__m128i, 4>>,
      false, true, key512, nonce512, 0, len, loop);
    #endif
    #ifdef __VAES__
    printf("m512i\n");
    test_perf<__m512i>(
      &rocca_encrypt<__m512i, 0, 1>,
      &rocca_decrypt<__m512i, 0, 1>,
      false, false, key512, nonce512, 0, len, loop);
    test_perf<__m512i>(
      &rocca_encrypt<__m512i, 0, 1>,
      &rocca_decrypt<__m512i, 0, 1>,
      false, true, key512, nonce512, 0, len, loop);
    #endif
  }
  printf("perf done");
}

int main()
{
  try {
    verify_test_vector();
    verify_misc();
    test_interleave();
    test_perf_len();
  } catch (std::exception const& ex) {
    printf("caught %s\n", ex.what());
    return 1;
  }
  return 0;
}

