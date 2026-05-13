#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hpdf.h"

static const char *kOwnerPassword = "owner-secret";
static const char *kUserPassword = "user-secret";
static const char *kTitle = "R6 Title";
static const char *kPageText = "Hello AES-256 R6";
#define K_IMAGE_WIDTH_MARKER "/Width 240"
#define K_IMAGE_HEIGHT_MARKER "/Height 320"
#define K_IMAGE_SUBTYPE_MARKER "/Subtype /Image"
#define K_IMAGE_COLORSPACE_MARKER "/ColorSpace /DeviceRGB"
#define K_PAGE_TEXT_REPEAT_COUNT 1024

static void
pdf_error_handler(HPDF_STATUS error_no, HPDF_STATUS detail_no, void *user_data)
{
    HPDF_UNUSED(user_data);
    fprintf(stderr, "libharu error: 0x%04X detail=%u\n",
            (unsigned int)error_no, (unsigned int)detail_no);
}

static int
read_file(const char *path, char **buf, size_t *len)
{
    FILE *fp;
    long size;

    *buf = NULL;
    *len = 0;

    fp = fopen(path, "rb");
    if (!fp)
        return 0;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return 0;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return 0;
    }

    *buf = (char *)malloc((size_t)size + 1);
    if (!*buf) {
        fclose(fp);
        return 0;
    }

    if (size > 0 && fread(*buf, 1, (size_t)size, fp) != (size_t)size) {
        free(*buf);
        *buf = NULL;
        fclose(fp);
        return 0;
    }

    (*buf)[size] = '\0';
    *len = (size_t)size;
    fclose(fp);
    return 1;
}

static int
contains_bytes(const char *buf, size_t buf_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t i;

    if (needle_len == 0 || buf_len < needle_len)
        return 0;

    for (i = 0; i + needle_len <= buf_len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0)
            return 1;
    }

    return 0;
}

static int
run_command_capture(const char *command, char *buf, size_t buf_size, int *exit_code)
{
    FILE *pipe;
    size_t used = 0;
    int status;

    pipe = popen(command, "r");
    if (!pipe)
        return 0;

    if (buf_size > 0)
        buf[0] = '\0';

    while (buf_size > 1 && fgets(buf + used, (int)(buf_size - used), pipe) != NULL) {
        used = strlen(buf);
        if (used >= buf_size - 1)
            break;
    }

    status = pclose(pipe);
    if (exit_code)
        *exit_code = status;
    return 1;
}

static int
generate_pdf(const char *output_path, const char *jpeg_path)
{
    HPDF_Doc pdf;
    HPDF_Page page;
    HPDF_Font font;
    HPDF_Image image = NULL;
    HPDF_STATUS ret;

    pdf = HPDF_New(pdf_error_handler, NULL);
    if (!pdf)
        return 0;

    ret = HPDF_SetInfoAttr(pdf, HPDF_INFO_TITLE, kTitle);
    ret |= HPDF_SetPassword(pdf, kOwnerPassword, kUserPassword);
    ret |= HPDF_SetEncryptionMode(pdf, HPDF_ENCRYPT_R6, 0);
#ifdef LIBHPDF_HAVE_ZLIB
    ret |= HPDF_SetCompressionMode(pdf, HPDF_COMP_ALL);
#endif
    if (ret != HPDF_OK) {
        HPDF_Free(pdf);
        return 0;
    }

    page = HPDF_AddPage(pdf);
    font = HPDF_GetFont(pdf, "Helvetica", NULL);
    if (!page || !font) {
        HPDF_Free(pdf);
        return 0;
    }

    ret = HPDF_Page_BeginText(page);
    ret |= HPDF_Page_SetFontAndSize(page, font, 18);
    if (ret == HPDF_OK) {
        HPDF_UINT i;

        for (i = 0; i < K_PAGE_TEXT_REPEAT_COUNT; i++) {
            ret = HPDF_Page_TextOut(page, 72, 720 - (HPDF_REAL)(i % 50) * 12,
                    kPageText);
            if (ret != HPDF_OK)
                break;
        }
    }
    ret |= HPDF_Page_EndText(page);
    if (ret != HPDF_OK) {
        HPDF_Free(pdf);
        return 0;
    }

    if (jpeg_path) {
        image = HPDF_LoadJpegImageFromFile(pdf, jpeg_path);
        if (!image) {
            HPDF_Free(pdf);
            return 0;
        }

        ret = HPDF_Page_DrawImage(page, image, 300, 72,
                HPDF_Image_GetWidth(image),
                HPDF_Image_GetHeight(image));
        if (ret != HPDF_OK) {
            HPDF_Free(pdf);
            return 0;
        }
    }

    ret = HPDF_SaveToFile(pdf, output_path);
    HPDF_Free(pdf);
    return ret == HPDF_OK;
}

static int
check_r6_key_length_rules(void)
{
    HPDF_Doc pdf;
    HPDF_STATUS ret;
    int ok = 1;

    pdf = HPDF_New(pdf_error_handler, NULL);
    if (!pdf)
        return 0;

    ret = HPDF_SetPassword(pdf, kOwnerPassword, kUserPassword);
    ok &= (ret == HPDF_OK);

    ret = HPDF_SetEncryptionMode(pdf, HPDF_ENCRYPT_R6, 0);
    ok &= (ret == HPDF_OK);

    ret = HPDF_SetEncryptionMode(pdf, HPDF_ENCRYPT_R6, 32);
    ok &= (ret == HPDF_OK);

    ret = HPDF_SetEncryptionMode(pdf, HPDF_ENCRYPT_R6, 16);
    ok &= (ret == HPDF_INVALID_ENCRYPT_KEY_LEN);
    ok &= (HPDF_GetError(pdf) == HPDF_INVALID_ENCRYPT_KEY_LEN);

    HPDF_Free(pdf);
    return ok;
}

static int
check_pdfa_encryption_conflicts(void)
{
    HPDF_Doc pdf;
    HPDF_STATUS ret;
    int ok = 1;

    pdf = HPDF_New(pdf_error_handler, NULL);
    if (!pdf)
        return 0;

    ret = HPDF_SetPDFAConformance(pdf, HPDF_PDFA_2B);
    ok &= (ret == HPDF_OK);

    ret = HPDF_SetPassword(pdf, kOwnerPassword, kUserPassword);
    ok &= (ret == HPDF_INVALID_OPERATION);
    ok &= (HPDF_GetError(pdf) == HPDF_INVALID_OPERATION);

    HPDF_Free(pdf);

    pdf = HPDF_New(pdf_error_handler, NULL);
    if (!pdf)
        return 0;

    ret = HPDF_SetPassword(pdf, kOwnerPassword, kUserPassword);
    ok &= (ret == HPDF_OK);

    ret = HPDF_SetPDFAConformance(pdf, HPDF_PDFA_2B);
    ok &= (ret == HPDF_INVALID_OPERATION);
    ok &= (HPDF_GetError(pdf) == HPDF_INVALID_OPERATION);

    HPDF_Free(pdf);
    return ok;
}

static int
check_structural_output(const char *path)
{
    char *buf;
    size_t len;
    int ok = 1;

    if (!read_file(path, &buf, &len))
        return 0;

    HPDF_UNUSED(len);
    ok &= contains_bytes(buf, len, "%PDF-1.7");
    ok &= contains_bytes(buf, len, "/R 6");
    ok &= contains_bytes(buf, len, "/V 5");
    ok &= contains_bytes(buf, len, "/Length 256");
    ok &= contains_bytes(buf, len, "/CFM /AESV3");
    ok &= !contains_bytes(buf, len, kTitle);
    ok &= !contains_bytes(buf, len, kPageText);

    free(buf);
    return ok;
}

static int
check_qpdf_roundtrip(const char *qpdf, const char *encrypted_path,
        int expect_image)
{
    char command[2048];
    char output[8192];
    char *decrypted_buf;
    size_t decrypted_len;
    int exit_code;
    int ok = 1;
    char decrypted_path[1024];

    snprintf(command, sizeof(command),
            "\"%s\" --password=%s --show-encryption \"%s\" 2>&1",
            qpdf, kUserPassword, encrypted_path);
    if (!run_command_capture(command, output, sizeof(output), &exit_code))
        return 0;
    ok &= (exit_code == 0);
    ok &= strstr(output, "R = 6") != NULL;
    ok &= strstr(output, "stream encryption method: AESv3") != NULL;
    ok &= strstr(output, "string encryption method: AESv3") != NULL;

    snprintf(command, sizeof(command),
            "\"%s\" --password=%s --decrypt \"%s\" \"%s.invalid\" 2>&1",
            qpdf, "wrong-password", encrypted_path, encrypted_path);
    if (!run_command_capture(command, output, sizeof(output), &exit_code))
        return 0;
    ok &= (exit_code != 0);
    ok &= strstr(output, "invalid password") != NULL;

    snprintf(decrypted_path, sizeof(decrypted_path), "%s.qdf.pdf",
            encrypted_path);
    snprintf(command, sizeof(command),
            "\"%s\" --password=%s --decrypt --qdf --object-streams=disable "
            "--stream-data=uncompress \"%s\" \"%s\" 2>&1",
            qpdf, kOwnerPassword, encrypted_path, decrypted_path);
    if (!run_command_capture(command, output, sizeof(output), &exit_code))
        return 0;
    ok &= (exit_code == 0);

    if (!read_file(decrypted_path, &decrypted_buf, &decrypted_len))
        return 0;

    HPDF_UNUSED(decrypted_len);
    ok &= contains_bytes(decrypted_buf, decrypted_len, kTitle);
    ok &= contains_bytes(decrypted_buf, decrypted_len, kPageText);
    if (expect_image) {
        ok &= contains_bytes(decrypted_buf, decrypted_len, K_IMAGE_SUBTYPE_MARKER);
        ok &= contains_bytes(decrypted_buf, decrypted_len, K_IMAGE_WIDTH_MARKER);
        ok &= contains_bytes(decrypted_buf, decrypted_len, K_IMAGE_HEIGHT_MARKER);
        ok &= contains_bytes(decrypted_buf, decrypted_len, K_IMAGE_COLORSPACE_MARKER);
    }
    free(decrypted_buf);

    remove(decrypted_path);
    snprintf(decrypted_path, sizeof(decrypted_path), "%s.invalid", encrypted_path);
    remove(decrypted_path);
    return ok;
}

int
main(int argc, char **argv)
{
    const char *output_path = NULL;
    const char *qpdf_path = NULL;
    const char *jpeg_path = NULL;
    int expect_image = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--qpdf") == 0 && i + 1 < argc) {
            qpdf_path = argv[++i];
        } else if (strcmp(argv[i], "--jpeg") == 0 && i + 1 < argc) {
            jpeg_path = argv[++i];
        } else if (strcmp(argv[i], "--expect-image") == 0) {
            expect_image = 1;
        }
    }

    if (!output_path) {
        fprintf(stderr, "--output is required\n");
        return 1;
    }

    if (!check_r6_key_length_rules()) {
        fprintf(stderr, "unexpected R6 key length behavior\n");
        return 1;
    }

    if (!check_pdfa_encryption_conflicts()) {
        fprintf(stderr, "PDF/A encryption conflict checks failed\n");
        return 1;
    }

    if (!generate_pdf(output_path, jpeg_path)) {
        fprintf(stderr, "failed to generate encrypted PDF\n");
        return 1;
    }

    if (!check_structural_output(output_path)) {
        fprintf(stderr, "encrypted PDF did not contain the expected R6 markers\n");
        return 1;
    }

    if (qpdf_path && !check_qpdf_roundtrip(qpdf_path, output_path, expect_image)) {
        fprintf(stderr, "qpdf validation failed\n");
        return 1;
    }

    return 0;
}
