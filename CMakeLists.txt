cmake_minimum_required(VERSION 3.12)

project(tecmp_converter)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(NOT CMAKE_BUILD_TYPE)
      set(CMAKE_BUILD_TYPE Debug CACHE STRING
          "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
          FORCE)
    endif()
endif()

# Configuration

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(cmake/libtecmp.cmake)
include(cmake/pcapng.cmake)
include(cmake/libpcap.cmake)
include(cmake/args.cmake)
include(cmake/pcapng_exporter.cmake)

# Let's nicely support folders in IDEs
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_executable(tecmp_converter 
    "src/app.cpp"
)

target_link_libraries(tecmp_converter
    pcapng_exporter tecmp_library light_pcapng libpcap args)
target_compile_features(tecmp_converter PRIVATE cxx_std_17)

if(WIN32)
    set_target_properties(tecmp_converter PROPERTIES LINK_FLAGS "/DELAYLOAD:wpcap.dll")
    target_link_libraries(tecmp_converter delayimp)
endif()

install(TARGETS tecmp_converter COMPONENT tecmp_converter)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Testing
    include(CTest)
    set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT tecmp_converter)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    
    # pcapng files tests
    list(APPEND pcapng_tests "caneth")
    list(APPEND pcapng_tests "tecmp_can_message")
    list(APPEND pcapng_tests "tecmp_eth_message")
    list(APPEND pcapng_tests "tecmp_can_pcapng")
    list(APPEND pcapng_tests "tecmp_can_tx")

    foreach(pcapng_test ${pcapng_tests})
        get_filename_component(param ${pcapng_test} NAME)
        string(REPLACE "/" "." param ${pcapng_test})
        add_test(
            NAME "convert.${param}"
            COMMAND tecmp_converter 
                "${CMAKE_CURRENT_LIST_DIR}/tests/input/${pcapng_test}.pcapng"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/${pcapng_test}.pcapng"
        )
    endforeach()
    
    # pcap files tests
    list(APPEND pcap_tests "tecmp_eth_message_pcap")
    list(APPEND pcap_tests "tecmp_can_messages_pcap")
    list(APPEND pcap_tests "tecmp_lin_messages_pcap")
    list(APPEND pcap_tests "tecmp_fr_null_frame_pcap")
    list(APPEND pcap_tests "tecmp_fr_sync_frame_pcap")

    foreach(pcap_test ${pcap_tests})
        get_filename_component(param ${pcap_test} NAME)
        string(REPLACE "/" "." param ${pcap_test})
        add_test(
            NAME "convert.${param}"
            COMMAND tecmp_converter 
                "${CMAKE_CURRENT_LIST_DIR}/tests/input/${pcap_test}.pcap"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/${pcap_test}.pcapng"
        )
    endforeach()

    # mapping files tests

    foreach(pcapng_test ${pcapng_tests})
        get_filename_component(param ${pcapng_test} NAME)
        string(REPLACE "/" "." param ${pcapng_test})
        add_test(
            NAME "mapping.${param}"
            COMMAND tecmp_converter
                "--channel-map" "${CMAKE_CURRENT_LIST_DIR}/tests/mapping.json"
                "${CMAKE_CURRENT_LIST_DIR}/tests/input/${pcapng_test}.pcapng"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/mapped/${pcapng_test}.pcapng"
        )
    endforeach()

    # TECMP-only tests
    list(APPEND tecmp_only_tests "dirty_tecmp")

    foreach(tecmp_only_test "${tecmp_only_tests}")
        add_test(
            NAME "${tecmp_only_test}.tecmp_only"
            COMMAND tecmp_converter "--tecmp-only"
                "${CMAKE_CURRENT_LIST_DIR}/tests/input/${tecmp_only_test}.pcapng"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/mapped/${tecmp_only_test}.pcapng"
        )
    endforeach()
endif()
