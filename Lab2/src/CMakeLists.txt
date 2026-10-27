add_library(rsa_core)

target_sources(rsa_core
    PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES
        FILES
            rsa.common.cppm
            rsa.number_theory.cppm
            rsa.prob_test.cppm
            rsa.core.cppm
            rsa.wiener.cppm
    PRIVATE
        rsa.number_theory.cpp
        rsa.prob_test.cpp
        rsa.wiener.cpp
)

target_link_libraries(rsa_core PUBLIC boost_headers)
