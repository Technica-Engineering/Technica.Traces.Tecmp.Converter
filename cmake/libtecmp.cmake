cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://git.ad.technica-engineering.de/akaanich/libtecmp.git
  GIT_TAG           90d7423d
)

FetchContent_MakeAvailable(libtecmp)

include_directories(${libtecmp_SOURCE_DIR}/include/)
