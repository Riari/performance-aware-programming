cmake_minimum_required(VERSION 3.27)
project(part1)

add_executable(part1 main.c)

add_custom_command(TARGET part1 POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy_directory
	${CMAKE_SOURCE_DIR}/listings/ $<TARGET_FILE_DIR:part1>/listings/)
