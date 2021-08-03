cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://github.com/Technica-Engineering/libtecmp.git
  GIT_TAG           629c9e9
)

FetchContent_MakeAvailable(libtecmp)
