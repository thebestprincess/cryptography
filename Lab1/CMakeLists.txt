find_package(TBB REQUIRED)

add_library(des_core
    source/DES.cpp
    source/paddings.cpp
    source/shared.cpp
    source/DEAL.cpp
)
target_include_directories(des_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(des_core PUBLIC TBB::tbb)

add_executable(MyDes
    source/main.cpp
)
target_link_libraries(MyDes PRIVATE des_core)
