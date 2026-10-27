add_executable(rsa_tests
    number_theory_tests.cpp
)

target_link_libraries(rsa_tests PRIVATE rsa_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(rsa_tests)