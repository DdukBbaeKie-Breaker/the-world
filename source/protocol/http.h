#pragma once
#include <stdint.h>

#define HTTP_METHOD_HTTP "HTTP"
#define HTTP_METHOD_GET "GET"
#define HTTP_METHOD_POST "POST"
#define HTTP_METHOD_PUT "PUT"
#define HTTP_METHOD_DELETE "DELETE"
#define HTTP_METHOD_CONNECT "CONNECT"
#define HTTP_METHOD_OPIONS "OPIONS"
#define HTTP_METHOD_TRACE "TRACE"
#define HTTP_METHOD_PATCH "PATCH"

struct httpmethod
{
    u_char * http_method;
    u_int len;
};