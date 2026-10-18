add_executable(des_tests
    tests.cpp
)

target_link_libraries(des_tests PRIVATE
    des_core
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(des_tests)