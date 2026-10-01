add_library(des_core
    DES.cpp
    paddings.cpp
    shared.cpp
    DEAL.cpp
)
target_include_directories(des_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(des_core PUBLIC TBB::tbb)

add_executable(MyDes main.cpp)
target_link_libraries(MyDes PRIVATE des_core)