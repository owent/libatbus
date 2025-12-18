#include <detail/libatbus_error.h>

#include <cstdint>
#include <string>

#include "frame/test_macros.h"

namespace {

template <class CharT>
static std::basic_string<CharT> unit_test_ascii_to_basic_string(const char *s) {
  std::basic_string<CharT> out;
  if (nullptr == s) {
    return out;
  }
  for (; '\0' != *s; ++s) {
    out.push_back(static_cast<CharT>(*s));
  }
  return out;
}

}  // namespace

CASE_TEST(libatbus_error, strerror_known_success) {
  const std::string &msg = libatbus_strerror(EN_ATBUS_ERR_SUCCESS);
  CASE_EXPECT_EQ(std::string("EN_ATBUS_ERR_SUCCESS(0): success"), msg);

  // Known errors are cached globally, repeated lookups should return the same object reference.
  const std::string &msg2 = libatbus_strerror(EN_ATBUS_ERR_SUCCESS);
  CASE_EXPECT_EQ(&msg, &msg2);
}

CASE_TEST(libatbus_error, strerror_known_samples) {
  CASE_EXPECT_EQ(std::string("EN_ATBUS_ERR_PARAMS(-1): ATBUS parameter error"), libatbus_strerror(EN_ATBUS_ERR_PARAMS));
  CASE_EXPECT_EQ(std::string("EN_ATBUS_ERR_NOT_READY(-607): not ready"), libatbus_strerror(EN_ATBUS_ERR_NOT_READY));
  CASE_EXPECT_EQ(std::string("EN_ATBUS_ERR_PIPE_ADDR_TOO_LONG(-504): pipe address too long"),
                 libatbus_strerror(EN_ATBUS_ERR_PIPE_ADDR_TOO_LONG));
}

CASE_TEST(libatbus_error, strerror_unknown_thread_local_cache) {
  const ATBUS_ERROR_TYPE code1 = static_cast<ATBUS_ERROR_TYPE>(12345);
  const ATBUS_ERROR_TYPE code2 = static_cast<ATBUS_ERROR_TYPE>(12346);

  const std::string &msg1 = libatbus_strerror(code1);
  CASE_EXPECT_EQ(std::string("ATBUS_ERROR_TYPE(12345): unknown"), msg1);

  // Unknown errors are cached per-thread. The object address should be stable in the same thread.
  const std::string &msg2 = libatbus_strerror(code2);
  CASE_EXPECT_EQ(&msg1, &msg2);
  CASE_EXPECT_EQ(std::string("ATBUS_ERROR_TYPE(12346): unknown"), msg2);
}

CASE_TEST(libatbus_error, wstrerror_known_and_unknown) {
  const std::wstring &known = libatbus_wstrerror(EN_ATBUS_ERR_SUCCESS);
  CASE_EXPECT_TRUE(known == std::wstring(L"EN_ATBUS_ERR_SUCCESS(0): success"));

  const std::wstring &unknown = libatbus_wstrerror(static_cast<ATBUS_ERROR_TYPE>(42));
  CASE_EXPECT_TRUE(unknown == std::wstring(L"ATBUS_ERROR_TYPE(42): unknown"));
}

#ifdef __cpp_unicode_characters
CASE_TEST(libatbus_error, u16_u32_strerror) {
  {
    const std::u16string &msg = libatbus_u16strerror(EN_ATBUS_ERR_SUCCESS);
    CASE_EXPECT_TRUE(msg == unit_test_ascii_to_basic_string<char16_t>("EN_ATBUS_ERR_SUCCESS(0): success"));
  }

  {
    const std::u32string &msg = libatbus_u32strerror(static_cast<ATBUS_ERROR_TYPE>(7));
    CASE_EXPECT_TRUE(msg == unit_test_ascii_to_basic_string<char32_t>("ATBUS_ERROR_TYPE(7): unknown"));
  }
}
#endif

#if defined(__cpp_char8_t) && (__cpp_char8_t >= 201811L) && (!defined(_HAS_CHAR8_T) || _HAS_CHAR8_T)
CASE_TEST(libatbus_error, u8_strerror) {
  const std::basic_string<char8_t> &msg = libatbus_u8strerror(EN_ATBUS_ERR_SUCCESS);
  CASE_EXPECT_TRUE(msg == unit_test_ascii_to_basic_string<char8_t>("EN_ATBUS_ERR_SUCCESS(0): success"));
}
#endif
