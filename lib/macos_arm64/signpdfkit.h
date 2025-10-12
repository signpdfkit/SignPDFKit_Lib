#ifdef __cplusplus
extern "C" {
#endif

int pdf_sign(const char *input_path,
              const char *output_path,
              const char *image_path,
              const char *url,
              const char *location,
              const char *reason,
              const char *contact_info,
              const char *field_id,
              const char *character,
              int signature_type,
              int page,
              int is_pades,
              int typ,
              double x,
              double y,
              double rect_width,
              double rect_height,
              char* (*sign_digest_func)(const char*),
              int dss);

const char* calculate_digest(const char *input_path,
              const char *image_path,
              const char *url,
              const char *location,
              const char *reason,
              const char *contact_info,
              const char *field_id,
              const char *character,
              int signature_type,
              int page,
              int is_pades,
              int typ,
              double x,
              double y,
              double rect_width,
              double rect_height,
              int dss);

int embed_cms(const char *pre_calculate,
              const char *cms,
              const char *output_path);

const char* get_revocation_parameters(const char *cms);

const char* verify(const char *input_path);

int is_signature_exist(const char *input_path);

void free_c_string(char* ptr);

#ifdef __cplusplus
}
#endif
