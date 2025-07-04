#include "imap/http_cal_abook_admin_js.h"

// Verifies that the last byte of imap/http_cal_abook_admin.js is \0 .
int main() {
    return http_cal_abook_admin_js[http_cal_abook_admin_js_len - 1] ? 1 : 0;
}
