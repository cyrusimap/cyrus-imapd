#ifdef __STDC__
#define assert(ex)	{if (!(ex))assertionfailed(__FILE__, __LINE__, #ex);}
#else
#define assert(ex)	{if (!(ex))assertionfailed(__FILE__, __LINE__, (char*)0);}
#endif
