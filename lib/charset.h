/* Marker to indicate characters that don't map to anything */
#define EMPTY_CHAR '\201'
#define EMPTY "\201"

#define ENCODING_NONE 0
#define ENCODING_QP 1
#define ENCODING_BASE64 2
#define ENCODING_UNKNOWN 255

int charset_lookupname(/* char *name */);
char *charset_convert(/* char *s, int charset */);
char *charset_decode1522(/* char *s */);

