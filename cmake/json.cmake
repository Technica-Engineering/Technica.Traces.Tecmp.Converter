cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY    https://github.com/nlohmann/json.git
  GIT_TAG           03270ef
  CMAKE_CACHE_ARGS  "-DMAIN_PROJECT:BOOL=OFF"
)

FetchContent_MakeAvailable(nlohmann_json)
