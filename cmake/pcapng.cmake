cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  pcapng
  GIT_REPOSITORY    https://github.com/woidpointer/LightPcapNg.git
  GIT_TAG           5934157
)

FetchContent_MakeAvailable(pcapng)
