
if (WIN32)
    include(FetchContent)
    FetchContent_Declare(
        npcap
        URL https://npcap.com/dist/npcap-sdk-1.12.zip
    )

    FetchContent_MakeAvailable(npcap)

    if (${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        # On x64 windows, we should look for the .lib at /Lib/x64
        list(APPEND CMAKE_PREFIX_PATH "${npcap_SOURCE_DIR}/Lib/x64")
    else()
        list(APPEND CMAKE_PREFIX_PATH "${npcap_SOURCE_DIR}/Lib")
    endif()
    
    list(APPEND CMAKE_PREFIX_PATH "${npcap_SOURCE_DIR}/Include")

endif()

find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap wpcap)

message(${PCAP_LIBRARY})
add_library(libpcap UNKNOWN IMPORTED)
SET_PROPERTY(TARGET libpcap PROPERTY IMPORTED_LOCATION "${PCAP_LIBRARY}")
target_include_directories(libpcap INTERFACE "${PCAP_INCLUDE_DIR}")
