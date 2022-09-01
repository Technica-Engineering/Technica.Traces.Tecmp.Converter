cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://github.com/aamereller/libtecmp.git
  GIT_TAG           85dd8b8
)

FetchContent_MakeAvailable(libtecmp)
