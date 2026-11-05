add_executable(rijndael_app
    main.cpp
)

target_link_libraries(rijndael_app PRIVATE rijndael_core)