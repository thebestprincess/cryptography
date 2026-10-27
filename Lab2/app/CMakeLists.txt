add_executable(crypto
    main.cpp
)

target_link_libraries(crypto PRIVATE rsa_core)