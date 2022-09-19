cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://github.com/aamereller/libtecmp.git
  GIT_TAG           917608e
)

FetchContent_MakeAvailable(libtecmp)
