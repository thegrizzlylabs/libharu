set(LIBHPDF_TEST_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/include
)

add_executable(test_encrypt_r6
    test_encrypt_r6.c
)
target_include_directories(test_encrypt_r6 PRIVATE ${LIBHPDF_TEST_INCLUDE_DIRS})
target_link_libraries(test_encrypt_r6 hpdf)

add_test(
    NAME encrypt_r6_struct
    COMMAND test_encrypt_r6
            --output ${CMAKE_CURRENT_BINARY_DIR}/encrypt_r6_struct.pdf
)

find_program(QPDF_EXECUTABLE qpdf)
if(QPDF_EXECUTABLE)
    add_test(
        NAME encrypt_r6_qpdf
        COMMAND test_encrypt_r6
                --output ${CMAKE_CURRENT_BINARY_DIR}/encrypt_r6_qpdf.pdf
                --qpdf ${QPDF_EXECUTABLE}
    )

    add_test(
        NAME encrypt_r6_image_qpdf
        COMMAND test_encrypt_r6
                --output ${CMAKE_CURRENT_BINARY_DIR}/encrypt_r6_image_qpdf.pdf
                --qpdf ${QPDF_EXECUTABLE}
                --jpeg ${PROJECT_SOURCE_DIR}/demo/images/rgb.jpg
                --expect-image
    )
endif()
