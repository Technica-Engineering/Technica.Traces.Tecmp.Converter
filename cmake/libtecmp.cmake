cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://github.com/Technica-Engineering/libtecmp.git
  GIT_TAG           85dd8b8
)

FetchContent_MakeAvailable(libtecmp)
