/* Marker to indicate characters that don't map to anything */
#define EMPTY_CHAR '\201'
#define EMPTY "\201"

int charset_lookupname(/* char *name */);
char *charset_convert(/* char *s, int charset */);
char *charset_decode1522(/* char *s */);

