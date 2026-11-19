find_package(TBB REQUIRED)

add_subdirectory(app)

add_library(rijndael_core
    src/galois_field.cpp
    src/paddings.cpp
)

target_include_directories(rijndael_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(rijndael_core PUBLIC boost_headers)
target_link_libraries(rijndael_core PUBLIC TBB::tbb)

if (BUILD_TESTING)
    add_subdirectory(tests)
endif()