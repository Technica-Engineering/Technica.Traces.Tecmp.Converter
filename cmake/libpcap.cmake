
if (WIN32)
    include(FetchContent)
    FetchContent_Declare(
        winpcap
        URL https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip
    )

    FetchContent_MakeAvailable(winpcap)

    if (${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        # On x64 windows, we should look for the .lib at /lib/x64/
        # as this is the default path for the WinPcap developer's pack
        list(APPEND CMAKE_PREFIX_PATH "${winpcap_SOURCE_DIR}/lib/x64/")
    endif()
    
    list(APPEND CMAKE_PREFIX_PATH "${winpcap_SOURCE_DIR}")

endif()

find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap wpcap)

message(${PCAP_LIBRARY})
add_library(libpcap UNKNOWN IMPORTED)
SET_PROPERTY(TARGET libpcap PROPERTY IMPORTED_LOCATION "${PCAP_LIBRARY}")
target_include_directories(libpcap INTERFACE "${PCAP_INCLUDE_DIR}")
