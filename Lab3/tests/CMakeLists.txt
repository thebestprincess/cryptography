add_executable(rijndael_tests
    tests.cpp
)

target_link_libraries(rijndael_tests PRIVATE rijndael_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(rijndael_tests)