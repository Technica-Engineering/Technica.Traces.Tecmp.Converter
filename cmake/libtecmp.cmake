cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  libtecmp
  GIT_REPOSITORY    https://github.com/RayanMRABET/libtecmp.git
  GIT_TAG           647dd73b71c1457b1bbf06542dd501ed7ef4330b
)

FetchContent_MakeAvailable(libtecmp)
