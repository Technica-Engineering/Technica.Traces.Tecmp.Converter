cmake_minimum_required(VERSION 3.12)

project(pcap_converter CXX)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(NOT CMAKE_BUILD_TYPE)
      set(CMAKE_BUILD_TYPE Debug CACHE STRING
          "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
          FORCE)
    endif()
endif()

# Configuration

include(cmake/libtecmp.cmake)
include(cmake/pcapng.cmake)
include(cmake/libpcap.cmake)

# Let's nicely support folders in IDEs
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_executable(pcap_converter "src/app.cpp" "src/endianness.h")
target_link_libraries(pcap_converter tecmp_library)
target_link_libraries(pcap_converter light_pcapng_static)
target_link_libraries(pcap_converter CONAN_PKG::winpcap)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Testing
    include(CTest)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    

    # pcapng files tests
    list(APPEND pcapng_tests "caneth")
    list(APPEND pcapng_tests "tecmp_can_message")
    list(APPEND pcapng_tests "tecmp_eth_message")
    list(APPEND pcapng_tests "tecmp_can_pcapng")

    foreach(pcapng_test ${pcapng_tests})
        get_filename_component(param ${pcapng_test} NAME)
        string(REPLACE "/" "." param ${pcapng_test})
        add_test(
            NAME "convert.${param}"
            COMMAND pcap_converter 
                "${CMAKE_CURRENT_LIST_DIR}/tests/input/${pcapng_test}.pcapng"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/${pcapng_test}.pcapng"
        )
    endforeach()
    
    # pcap files tests
    list(APPEND pcap_tests "tecmp_eth_message_pcap")
    list(APPEND pcap_tests "tecmp_can_messages_pcap")

    foreach(pcap_test ${pcap_tests})
        get_filename_component(param ${pcap_test} NAME)
        string(REPLACE "/" "." param ${pcap_test})
        add_test(
            NAME "convert.${param}"
            COMMAND pcap_converter 
                "${CMAKE_CURRENT_LIST_DIR}/tests/input/${pcap_test}.pcap"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/${pcap_test}.pcapng"
        )
    endforeach()
endif()
