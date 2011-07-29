#include "config.h"
#include "cunit/cunit.h"
#include "tok.h"

#define WORD0	"lorem"
#define WORD1	"ipsum"
#define WORD2	"dolor"
#define WORD3	"sit"
#define WORD4	"amet"

static void test_simple(void)
{
    static const char PHRASE[] = WORD0" "WORD1" "WORD2" "WORD3" "WORD4;
    tok_t tok = TOK_INITIALIZER(PHRASE, NULL, 0);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_init(void)
{
    static const char PHRASE[] = WORD0" "WORD1" "WORD2" "WORD3" "WORD4;
    tok_t tok;
    char *p;

    tok_init(&tok, PHRASE, NULL, 0);

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_initm(void)
{
    static const char PHRASE[] = WORD0" "WORD1" "WORD2" "WORD3" "WORD4;
    tok_t tok;
    char *p;
    char buf[1024];

    strcpy(buf, PHRASE);
    tok_initm(&tok, buf, NULL, 0);

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_freebuffer(void)
{
    static const char PHRASE[] = WORD0" "WORD1" "WORD2" "WORD3" "WORD4;
    tok_t tok;
    char *p;

    tok_initm(&tok, xstrdup(PHRASE), NULL, TOK_FREEBUFFER);

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);

}

static void test_multiple_delim(void)
{
    static const char PHRASE[] = WORD0"    "WORD1" \t  "WORD2"\r"WORD3"\r\n \t\t\t "WORD4;
    tok_t tok = TOK_INITIALIZER(PHRASE, NULL, 0);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_nondefault_delim(void)
{
    static const char PHRASE[] = WORD0","WORD1","WORD2","WORD3","WORD4;
    tok_t tok = TOK_INITIALIZER(PHRASE, ",", 0);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_empty(void)
{
    static const char PHRASE[] = ","WORD0","WORD1",,,"WORD2","WORD3","WORD4",";
    tok_t tok = TOK_INITIALIZER(PHRASE, ",", TOK_EMPTY);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, "");
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, "");
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, "");
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, "");
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_trimleft(void)
{
    static const char PHRASE[] = " "WORD0",\t"WORD1" ,\r\n "WORD2",    "WORD3","WORD4;
    tok_t tok = TOK_INITIALIZER(PHRASE, ",", TOK_TRIMLEFT);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1" ");
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_trimright(void)
{
    static const char PHRASE[] = WORD0","WORD1"\t, "WORD2"\r\n ,"WORD3" ,"WORD4" ";
    tok_t tok = TOK_INITIALIZER(PHRASE, ",", TOK_TRIMRIGHT);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, " "WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_trimboth(void)
{
    static const char PHRASE[] = " "WORD0" \t,"WORD1"\t, "WORD2"\r\n , "WORD3" \t ,"WORD4"\r\n";
    tok_t tok = TOK_INITIALIZER(PHRASE, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_offset(void)
{
    static const char PHRASE[] = WORD0" "WORD1" "WORD2" "WORD3" "WORD4;
    tok_t tok = TOK_INITIALIZER(PHRASE, NULL, 0);
    char *p;

    CU_ASSERT_EQUAL(tok_offset(&tok), 0);

    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    CU_ASSERT_EQUAL(tok_offset(&tok), 0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    CU_ASSERT_EQUAL(tok_offset(&tok), sizeof(WORD0" ")-1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    CU_ASSERT_EQUAL(tok_offset(&tok), sizeof(WORD0" "WORD1" ")-1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    CU_ASSERT_EQUAL(tok_offset(&tok),
		    sizeof(WORD0" "WORD1" "WORD2" ")-1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    CU_ASSERT_EQUAL(tok_offset(&tok),
		    sizeof(WORD0" "WORD1" "WORD2" "WORD3" " )-1);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_stopearly(void)
{
    static const char PHRASE[] = WORD0" "WORD1" "WORD2" "WORD3" "WORD4;
    tok_t tok = TOK_INITIALIZER(PHRASE, NULL, 0);
    char *p;

    /* test that ceasing to call tok_next() before the end
     * of the tokens does not leak memory as long as tok_fini()
     * is called; we rely on Valgrind to find memleaks */
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);

    tok_fini(&tok);
}

static void test_nofini(void)
{
    static const char PHRASE[] = WORD0" "WORD1" "WORD2" "WORD3" "WORD4;
    tok_t tok = TOK_INITIALIZER(PHRASE, NULL, 0);
    char *p;

    /* test the converse of stopearly, i.e. that tok_fini() is
     * not necessary if all the tokens are read with tok_next();
     * again we rely on Valgrind to find memleaks */
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD0);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD1);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD2);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD3);
    p = tok_next(&tok);
    CU_ASSERT_STRING_EQUAL(p, WORD4);
    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    /* no tok_fini */
}

static void test_blank(void)
{
    static const char PHRASE[] = "";
    tok_t tok = TOK_INITIALIZER(PHRASE, NULL, 0);
    char *p;

    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_initnull(void)
{
    tok_t tok;
    char *p;

    tok_init(&tok, NULL, NULL, 0);

    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

static void test_initmnull(void)
{
    tok_t tok;
    char *p;

    tok_initm(&tok, NULL, NULL, 0);

    p = tok_next(&tok);
    CU_ASSERT_PTR_NULL(p);

    tok_fini(&tok);
}

