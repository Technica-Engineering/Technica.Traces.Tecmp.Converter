cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://git.ad.technica-engineering.de/technica.traces/libtecmp.git
  GIT_TAG           3ae34b8b
)

FetchContent_MakeAvailable(libtecmp)
