/* Definitions internal to charset.c and chartable.c */

#define XLT 'N'			/* Long translation */
#define U7F 'O'			/* UTF-7 first base64 character */
#define U7N 'P'			/* UTF-7 subsquent base64 character */
#define U83 'Q'			/* UTF-8 3-char sequence */
#define U83_2 'R'		/* second char of same */
#define U83_3 'S'		/* third char of same */
#define JSR 'T'
#define JMP 'U'
#define RET 'V'
#define END 'W'

struct charset {
    char *name;
    const unsigned char (*table)[256][4];
};


