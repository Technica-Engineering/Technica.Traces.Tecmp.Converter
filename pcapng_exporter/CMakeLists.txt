
add_library(pcapng_exporter
    STATIC
    "mapping.cpp"
    "pcapng_exporter.cpp"
)
target_include_directories(pcapng_exporter 
    PUBLIC
    "include"
)
target_link_libraries(pcapng_exporter
    PUBLIC
    light_pcapng_static
    PRIVATE
    nlohmann_json
)
target_compile_features(pcapng_exporter PUBLIC cxx_std_17)
