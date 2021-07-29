cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://github.com/Technica-Engineering/libtecmp.git
  GIT_TAG           4e98c29
)

FetchContent_MakeAvailable(libtecmp)
