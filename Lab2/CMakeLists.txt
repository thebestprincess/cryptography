set(CMAKE_CXX_MODULE_STD ON)

include(FetchContent)

FetchContent_Declare(
    boost
    URL https://archives.boost.io/release/1.92.0/source/boost_1_92_0.tar.bz2
    URL_HASH SHA256=5c1d40cb8e19adbf740a4ec2da35b3e58f3f5804b1dce44deb53df72193cbc6c
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(boost)

add_library(boost_headers INTERFACE)
target_include_directories(boost_headers SYSTEM INTERFACE "${boost_SOURCE_DIR}")

add_subdirectory(src)
add_subdirectory(app)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()