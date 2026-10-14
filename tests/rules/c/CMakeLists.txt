cmake_minimum_required(VERSION 3.20)
project(demo C)
# ruleid: c.stack-protector-off
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
# ok: c.stack-protector-off
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=3")
