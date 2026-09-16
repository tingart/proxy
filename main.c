#define _GNU_SOURCE

#include <microhttpd.h>
#include <curl/curl.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 10000

#define DAILY_LIMIT_SECONDS (10 * 60)
#define SESSION_TTL_SECONDS (6 * 60 * 60)
#define INJECTION_TTL_SECONDS (60 * 60)

#define MAX_BODY (64ULL * 1024ULL * 1024ULL)
#define MAX_HTML (20ULL * 1024ULL * 1024ULL)
#define MAX_INJECTION (2ULL * 1024ULL * 1024ULL)

#define SID_LEN 32


/* =========================================================
   BUFFER
========================================================= */

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} Buffer;


static void buffer_free(Buffer *b)
{
    if (!b)
        return;

    free(b->data);

    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}


static int buffer_reserve(Buffer *b, size_t extra)
{
    if (!b)
        return 0;

    if (extra > MAX_BODY)
        return 0;

    if (b->len > MAX_BODY - extra)
        return 0;

    size_t needed = b->len + extra;

    if (needed <= b->cap)
        return 1;

    size_t cap = b->cap ? b->cap : 8192;

    while (cap < needed)
    {
        if (cap > MAX_BODY / 2)
        {
            cap = MAX_BODY;
            break;
        }

        cap *= 2;
    }

    unsigned char *p = realloc(
        b->data,
        cap
    );

    if (!p)
        return 0;

    b->data = p;
    b->cap = cap;

    return 1;
}


static int buffer_append(
    Buffer *b,
    const void *data,
    size_t n
)
{
    if (!n)
        return 1;

    if (!buffer_reserve(b, n))
        return 0;

    memcpy(
        b->data + b->len,
        data,
        n
    );

    b->len += n;

    return 1;
}


/* =========================================================
   HELPERS
========================================================= */

static char *xstrdup(
    const char *s
)
{
    return s ? strdup(s) : NULL;
}


static char *trimdup(
    const char *s,
    size_t n
)
{
    while (
        n &&
        isspace((unsigned char)*s)
    )
    {
        s++;
        n--;
    }

    while (
        n &&
        isspace((unsigned char)s[n - 1])
    )
    {
        n--;
    }

    char *r = malloc(n + 1);

    if (!r)
        return NULL;

    memcpy(r, s, n);

    r[n] = 0;

    return r;
}


static char *lowerdup(
    const char *s
)
{
    if (!s)
        return NULL;

    size_t n = strlen(s);

    char *r = malloc(n + 1);

    if (!r)
        return NULL;

    for (
        size_t i = 0;
        i < n;
        i++
    )
    {
        r[i] =
            (char)tolower(
                (unsigned char)s[i]
            );
    }

    r[n] = 0;

    return r;
}


static int is_http_url(
    const char *url
)
{
    if (!url)
        return 0;

    return
        !strncasecmp(
            url,
            "http://",
            7
        )
        ||
        !strncasecmp(
            url,
            "https://",
            8
        );
}


static char *url_host(
    const char *url
)
{
    if (!url)
        return NULL;

    const char *p =
        strstr(url, "://");

    if (!p)
        return NULL;

    p += 3;

    const char *e =
        strpbrk(
            p,
            "/?#"
        );

    if (!e)
        e = p + strlen(p);

    const char *colon =
        memchr(
            p,
            ':',
            (size_t)(e - p)
        );

    if (colon)
        e = colon;

    return trimdup(
        p,
        (size_t)(e - p)
    );
}


static char *url_origin(
    const char *url
)
{
    const char *p =
        strstr(url, "://");

    if (!p)
        return NULL;

    p += 3;

    const char *e =
        strpbrk(
            p,
            "/?#"
        );

    if (!e)
        e = p + strlen(p);

    size_t n =
        (size_t)(e - url);

    char *r =
        malloc(n + 1);

    if (!r)
        return NULL;

    memcpy(r, url, n);

    r[n] = 0;

    return r;
}


static char *url_path(
    const char *url
)
{
    const char *p =
        strstr(url, "://");

    if (!p)
        return strdup("/");

    p += 3;

    p = strchr(p, '/');

    if (!p)
        return strdup("/");

    const char *e =
        strpbrk(
            p,
            "?#"
        );

    size_t n =
        e
            ? (size_t)(e - p)
            : strlen(p);

    if (!n)
        return strdup("/");

    return trimdup(
        p,
        n
    );
}


/* =========================================================
   SESSION COOKIE JAR
========================================================= */

typedef struct Cookie {
    char *name;
    char *value;
    char *domain;
    char *path;

    int secure;

    struct Cookie *next;

} Cookie;


typedef struct Session {

    char sid[SID_LEN + 1];

    char *target;
    char *origin;

    time_t created;
    time_t last_used;

    Cookie *cookies;

    unsigned long used_seconds;
    time_t budget_day;

    struct Session *next;

} Session;


static pthread_mutex_t session_lock =
    PTHREAD_MUTEX_INITIALIZER;

static Session *sessions = NULL;


static void free_cookie(
    Cookie *c
)
{
    if (!c)
        return;

    free(c->name);
    free(c->value);
    free(c->domain);
    free(c->path);

    free(c);
}


static void free_cookies(
    Cookie *c
)
{
    while (c)
    {
        Cookie *next =
            c->next;

        free_cookie(c);

        c = next;
    }
}


static void free_session(
    Session *s
)
{
    if (!s)
        return;

    free(s->target);
    free(s->origin);

    free_cookies(
        s->cookies
    );

    free(s);
}


static int domain_match(
    const char *host,
    const char *domain
)
{
    if (!host || !domain)
        return 0;

    while (*domain == '.')
        domain++;

    size_t hn =
        strlen(host);

    size_t dn =
        strlen(domain);

    if (hn == dn)
        return !strcasecmp(
            host,
            domain
        );

    if (hn <= dn)
        return 0;

    return
        !strcasecmp(
            host + hn - dn,
            domain
        )
        &&
        host[hn - dn - 1] == '.';
}


static int path_match(
    const char *path,
    const char *cookie_path
)
{
    if (
        !cookie_path ||
        !*cookie_path
    )
    {
        return 1;
    }

    return
        !strncmp(
            path,
            cookie_path,
            strlen(cookie_path)
        );
}


static void random_sid(
    char out[SID_LEN + 1]
)
{
    static const char hex[] =
        "0123456789abcdef";

    unsigned char bytes[16];

    FILE *f =
        fopen(
            "/dev/urandom",
            "rb"
        );

    if (f)
    {
        fread(
            bytes,
            1,
            sizeof(bytes),
            f
        );

        fclose(f);
    }
    else
    {
        unsigned long seed =
            (unsigned long)time(NULL)
            ^
            (unsigned long)getpid();

        for (
            size_t i = 0;
            i < sizeof(bytes);
            i++
        )
        {
            seed =
                seed *
                1103515245u
                +
                12345u;

            bytes[i] =
                (unsigned char)(
                    seed >> 24
                );
        }
    }

    for (
        size_t i = 0;
        i < sizeof(bytes);
        i++
    )
    {
        out[i * 2] =
            hex[
                bytes[i] >> 4
            ];

        out[i * 2 + 1] =
            hex[
                bytes[i] & 15
            ];
    }

    out[SID_LEN] = 0;
}


static Session *find_session(
    const char *sid
)
{
    if (!sid)
        return NULL;

    Session *s = sessions;

    while (s)
    {
        if (!strcmp(
            s->sid,
            sid
        ))
        {
            return s;
        }

        s = s->next;
    }

    return NULL;
}


static Session *create_session(
    const char *target
)
{
    Session *s =
        calloc(
            1,
            sizeof(*s)
        );

    if (!s)
        return NULL;

    random_sid(
        s->sid
    );

    s->target =
        strdup(target);

    s->origin =
        url_origin(target);

    s->created =
        time(NULL);

    s->last_used =
        s->created;

    s->budget_day =
        s->created;

    pthread_mutex_lock(
        &session_lock
    );

    s->next =
        sessions;

    sessions =
        s;

    pthread_mutex_unlock(
        &session_lock
    );

    return s;
}


static void touch_session(
    Session *s
)
{
    if (s)
        s->last_used =
            time(NULL);
}


/* =========================================================
   COOKIE STORAGE
========================================================= */

static void delete_cookie(
    Session *s,
    const char *name,
    const char *domain,
    const char *path
)
{
    Cookie **pp =
        &s->cookies;

    while (*pp)
    {
        Cookie *c =
            *pp;

        if (
            !strcasecmp(
                c->name,
                name
            )
            &&
            !strcasecmp(
                c->domain,
                domain
            )
            &&
            !strcmp(
                c->path,
                path
            )
        )
        {
            *pp =
                c->next;

            free_cookie(c);

            return;
        }

        pp =
            &c->next;
    }
}


static void store_cookie(
    Session *s,
    const char *raw,
    const char *url
)
{
    if (
        !s ||
        !raw ||
        !*raw
    )
        return;

    char *tmp =
        strdup(raw);

    if (!tmp)
        return;

    char *semi =
        strchr(
            tmp,
            ';'
        );

    if (semi)
        *semi = 0;

    char *eq =
        strchr(
            tmp,
            '='
        );

    if (!eq)
    {
        free(tmp);
        return;
    }

    *eq = 0;

    char *name =
        trimdup(
            tmp,
            strlen(tmp)
        );

    char *value =
        trimdup(
            eq + 1,
            strlen(eq + 1)
        );

    if (
        !name ||
        !value ||
        !*name
    )
    {
        free(name);
        free(value);
        free(tmp);
        return;
    }

    char *domain =
        url_host(url);

    char *path =
        strdup("/");

    int secure = 0;
    int deleted = 0;

    if (semi)
    {
        char *p =
            semi + 1;

        while (p && *p)
        {
            char *next =
                strchr(
                    p,
                    ';'
                );

            if (next)
                *next = 0;

            while (
                *p &&
                isspace(
                    (unsigned char)*p
                )
            )
                p++;

            char *a =
                strchr(
                    p,
                    '='
                );

            if (a)
            {
                *a = 0;

                char *key =
                    lowerdup(p);

                char *val =
                    trimdup(
                        a + 1,
                        strlen(a + 1)
                    );

                if (
                    key &&
                    val
                )
                {
                    if (
                        !strcmp(
                            key,
                            "domain"
                        )
                    )
                    {
                        free(domain);

                        domain =
                            strdup(val);

                        if (
                            domain &&
                            domain[0] == '.'
                        )
                        {
                            memmove(
                                domain,
                                domain + 1,
                                strlen(domain)
                            );
                        }
                    }
                    else if (
                        !strcmp(
                            key,
                            "path"
                        )
                    )
                    {
                        free(path);

                        path =
                            strdup(val);
                    }
                    else if (
                        !strcmp(
                            key,
                            "max-age"
                        )
                    )
                    {
                        if (
                            atoi(val) <= 0
                        )
                            deleted = 1;
                    }
                }

                free(key);
                free(val);
            }
            else
            {
                char *key =
                    lowerdup(p);

                if (
                    key &&
                    !strcmp(
                        key,
                        "secure"
                    )
                )
                    secure = 1;

                free(key);
            }

            if (!next)
                break;

            p =
                next + 1;
        }
    }

    if (!domain)
        domain =
            url_host(url);

    if (deleted)
    {
        delete_cookie(
            s,
            name,
            domain,
            path
        );
    }
    else
    {
        Cookie *found =
            NULL;

        for (
            Cookie *c =
                s->cookies;
            c;
            c = c->next
        )
        {
            if (
                !strcasecmp(
                    c->name,
                    name
                )
                &&
                !strcasecmp(
                    c->domain,
                    domain
                )
                &&
                !strcmp(
                    c->path,
                    path
                )
            )
            {
                found = c;
                break;
            }
        }

        if (found)
        {
            free(found->value);

            found->value =
                value;

            found->secure =
                secure;

            value = NULL;
        }
        else
        {
            Cookie *c =
                calloc(
                    1,
                    sizeof(*c)
                );

            if (c)
            {
                c->name = name;
                c->value = value;
                c->domain = domain;
                c->path = path;
                c->secure = secure;

                c->next =
                    s->cookies;

                s->cookies =
                    c;

                name = NULL;
                value = NULL;
                domain = NULL;
                path = NULL;
            }
        }
    }

    free(name);
    free(value);
    free(domain);
    free(path);
    free(tmp);
}


static char *cookie_header(
    Session *s,
    const char *url
)
{
    char *host =
        url_host(url);

    char *path =
        url_path(url);

    if (
        !host ||
        !path
    )
    {
        free(host);
        free(path);
        return NULL;
    }

    size_t cap = 256;
    size_t len = 0;

    char *out =
        malloc(cap);

    if (!out)
    {
        free(host);
        free(path);
        return NULL;
    }

    out[0] = 0;

    for (
        Cookie *c =
            s->cookies;
        c;
        c = c->next
    )
    {
        if (
            !domain_match(
                host,
                c->domain
            )
        )
            continue;

        if (
            !path_match(
                path,
                c->path
            )
        )
            continue;

        if (
            c->secure &&
            strncasecmp(
                url,
                "https://",
                8
            )
        )
            continue;

        size_t needed =
            strlen(c->name)
            +
            strlen(c->value)
            +
            4;

        if (
            len +
            needed +
            1 >
            cap
        )
        {
            cap *= 2;

            char *p =
                realloc(
                    out,
                    cap
                );

            if (!p)
                break;

            out = p;
        }

        if (len)
        {
            out[len++] = ';';
            out[len++] = ' ';
        }

        len +=
            sprintf(
                out + len,
                "%s=%s",
                c->name,
                c->value
            );
    }

    out[len] = 0;

    free(host);
    free(path);

    if (!len)
    {
        free(out);
        return NULL;
    }

    return out;
}


/* =========================================================
   RESPONSE HEADERS
========================================================= */

typedef struct HeaderNode {

    char *name;
    char *value;

    struct HeaderNode *next;

} HeaderNode;


static void free_headers(
    HeaderNode *h
)
{
    while (h)
    {
        HeaderNode *next =
            h->next;

        free(h->name);
        free(h->value);
        free(h);

        h = next;
    }
}


static void add_header(
    HeaderNode **list,
    const char *name,
    const char *value
)
{
    HeaderNode *h =
        calloc(
            1,
            sizeof(*h)
        );

    if (!h)
        return;

    h->name =
        strdup(name);

    h->value =
        strdup(value);

    h->next =
        *list;

    *list =
        h;
}


static const char *get_header(
    HeaderNode *list,
    const char *name
)
{
    for (
        HeaderNode *h =
            list;
        h;
        h = h->next
    )
    {
        if (
            !strcasecmp(
                h->name,
                name
            )
        )
        {
            return h->value;
        }
    }

    return NULL;
}


static int forward_header(
    const char *name
)
{
    const char *blocked[] = {

        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",

        "content-length",
        "content-encoding",

        "set-cookie",

        "x-frame-options",

        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",

        NULL

    };

    for (
        int i = 0;
        blocked[i];
        i++
    )
    {
        if (
            !strcasecmp(
                name,
                blocked[i]
            )
        )
            return 0;
    }

    return 1;
}


/* =========================================================
   CSP
========================================================= */

static char *sanitize_csp(
    const char *csp
)
{
    if (!csp)
        return NULL;

    char *copy =
        strdup(csp);

    if (!copy)
        return NULL;

    size_t cap =
        strlen(csp) + 1;

    char *out =
        malloc(cap);

    if (!out)
    {
        free(copy);
        return NULL;
    }

    out[0] = 0;

    size_t len = 0;

    char *save = NULL;

    char *part =
        strtok_r(
            copy,
            ";",
            &save
        );

    while (part)
    {
        while (
            isspace(
                (unsigned char)*part
            )
        )
            part++;

        char *low =
            lowerdup(part);

        int remove =
            low &&
            strstr(
                low,
                "frame-ancestors"
            );

        free(low);

        if (!remove)
        {
            size_t n =
                strlen(part);

            if (
                len +
                n +
                3 >=
                cap
            )
            {
                cap *= 2;

                char *p =
                    realloc(
                        out,
                        cap
                    );

                if (!p)
                {
                    free(copy);
                    free(out);
                    return NULL;
                }

                out = p;
            }

            if (len)
            {
                out[len++] = ';';
                out[len++] = ' ';
            }

            memcpy(
                out + len,
                part,
                n
            );

            len += n;

            out[len] = 0;
        }

        part =
            strtok_r(
                NULL,
                ";",
                &save
            );
    }

    free(copy);

    return out;
}


/* =========================================================
   URL BASE64URL
========================================================= */

static const char BASE64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";


static char *encode_url(
    const char *url
)
{
    size_t n =
        strlen(url);

    size_t cap =
        ((n + 2) / 3) * 4 + 1;

    char *out =
        malloc(cap);

    if (!out)
        return NULL;

    size_t i = 0;
    size_t j = 0;

    while (i < n)
    {
        unsigned a =
            (unsigned char)url[i++];

        unsigned b =
            i < n
                ? (unsigned char)url[i++]
                : 0;

        unsigned c =
            i < n
                ? (unsigned char)url[i++]
                : 0;

        out[j++] =
            BASE64URL[
                a >> 2
            ];

        out[j++] =
            BASE64URL[
                ((a & 3) << 4)
                |
                (b >> 4)
            ];

        if (i - 1 < n)
        {
            out[j++] =
                BASE64URL[
                    ((b & 15) << 2)
                    |
                    (c >> 6)
                ];
        }

        if (i <= n)
        {
            out[j++] =
                BASE64URL[
                    c & 63
                ];
        }
    }

    size_t rem =
        n % 3;

    if (rem == 1)
        j -= 2;
    else if (rem == 2)
        j -= 1;

    out[j] = 0;

    return out;
}


static int b64value(
    char c
)
{
    if (
        c >= 'A' &&
        c <= 'Z'
    )
        return c - 'A';

    if (
        c >= 'a' &&
        c <= 'z'
    )
        return c - 'a' + 26;

    if (
        c >= '0' &&
        c <= '9'
    )
        return c - '0' + 52;

    if (c == '-')
        return 62;

    if (c == '_')
        return 63;

    return -1;
}


static char *decode_url(
    const char *s
)
{
    size_t n =
        strlen(s);

    char *out =
        malloc(
            n + 1
        );

    if (!out)
        return NULL;

    int val = 0;
    int bits = -8;

    size_t oi = 0;

    for (
        size_t i = 0;
        i < n;
        i++
    )
    {
        int v =
            b64value(
                s[i]
            );

        if (v < 0)
            continue;

        val =
            (val << 6)
            |
            v;

        bits += 6;

        if (bits >= 0)
        {
            out[oi++] =
                (char)(
                    (val >> bits)
                    & 255
                );

            bits -= 8;
        }
    }

    out[oi] = 0;

    return out;
}


static char *proxy_url(
    const char *url,
    const char *sid
)
{
    char *enc =
        encode_url(url);

    if (!enc)
        return NULL;

    size_t n =
        strlen(enc)
        +
        strlen(sid)
        +
        20;

    char *out =
        malloc(n);

    if (out)
    {
        snprintf(
            out,
            n,
            "/proxy/%s/%s",
            sid,
            enc
        );
    }

    free(enc);

    return out;
}


/* =========================================================
   URL RESOLUTION
========================================================= */

static char *absolute_url(
    const char *base,
    const char *value
)
{
    if (
        !value ||
        !*value
    )
        return NULL;

    CURLU *u =
        curl_url();

    if (!u)
        return NULL;

    char *result = NULL;

    if (
        curl_url_set(
            u,
            CURLUPART_URL,
            base,
            0
        )
        != CURLUE_OK
    )
        goto done;

    if (
        curl_url_set(
            u,
            CURLUPART_URL,
            value,
            0
        )
        != CURLUE_OK
    )
        goto done;

    curl_url_get(
        u,
        CURLUPART_URL,
        &result,
        0
    );

done:

    curl_url_cleanup(u);

    return result;
}


static int skip_url(
    const char *value
)
{
    if (
        !value ||
        !*value
    )
        return 1;

    while (
        isspace(
            (unsigned char)*value
        )
    )
        value++;

    return
        value[0] == '#'
        ||
        !strncasecmp(
            value,
            "javascript:",
            11
        )
        ||
        !strncasecmp(
            value,
            "data:",
            5
        )
        ||
        !strncasecmp(
            value,
            "blob:",
            5
        )
        ||
        !strncasecmp(
            value,
            "mailto:",
            7
        )
        ||
        !strncasecmp(
            value,
            "tel:",
            4
        )
        ||
        !strncasecmp(
            value,
            "about:",
            6
        )
        ||
        !strncasecmp(
            value,
            "chrome:",
            7
        )
        ||
        !strncasecmp(
            value,
            "file:",
            5
        );
}


/* =========================================================
   HTML REWRITER
========================================================= */

static char *rewrite_attrs(
    const char *html,
    const char *target,
    const char *sid
)
{
    const char *attrs[] = {

        "href",
        "src",
        "action",
        "poster",
        "formaction",

        "data-src",
        "data-href",
        "data-url",
        "data-action",

        NULL
    };

    size_t inlen =
        strlen(html);

    size_t cap =
        inlen + 8192;

    char *out =
        malloc(cap);

    if (!out)
        return NULL;

    size_t oi = 0;

    for (
        size_t i = 0;
        i < inlen;
    )
    {
        int found = 0;

        const char *attr = NULL;

        size_t alen = 0;

        for (
            int a = 0;
            attrs[a];
            a++
        )
        {
            size_t n =
                strlen(
                    attrs[a]
                );

            if (
                i + n <= inlen
                &&
                !strncasecmp(
                    html + i,
                    attrs[a],
                    n
                )
                &&
                (
                    i == 0
                    ||
                    !isalnum(
                        (unsigned char)
                        html[i - 1]
                    )
                )
            )
            {
                found = 1;
                attr = attrs[a];
                alen = n;
                break;
            }
        }

        if (!found)
        {
            if (
                oi + 2 >= cap
            )
            {
                cap *= 2;

                char *p =
                    realloc(
                        out,
                        cap
                    );

                if (!p)
                {
                    free(out);
                    return NULL;
                }

                out = p;
            }

            out[oi++] =
                html[i++];

            continue;
        }

        size_t p =
            i + alen;

        while (
            p < inlen &&
            isspace(
                (unsigned char)
                html[p]
            )
        )
            p++;

        if (
            p >= inlen ||
            html[p] != '='
        )
        {
            out[oi++] =
                html[i++];

            continue;
        }

        p++;

        while (
            p < inlen &&
            isspace(
                (unsigned char)
                html[p]
            )
        )
            p++;

        char quote = 0;

        if (
            p < inlen &&
            (
                html[p] == '"' ||
                html[p] == '\''
            )
        )
        {
            quote =
                html[p++];
        }

        size_t start = p;

        while (
            p < inlen
            &&
            (
                quote
                    ? html[p] != quote
                    : (
                        !isspace(
                            (unsigned char)
                            html[p]
                        )
                        &&
                        html[p] != '>'
                    )
            )
        )
            p++;

        size_t vn =
            p - start;

        char *value =
            trimdup(
                html + start,
                vn
            );

        char *abs =
            absolute_url(
                target,
                value
            );

        char *proxied = NULL;

        if (
            abs &&
            is_http_url(abs)
        )
        {
            proxied =
                proxy_url(
                    abs,
                    sid
                );
        }

        const char *use =
            proxied
                ? proxied
                : value;

        size_t needed =
            alen
            +
            1
            +
            strlen(use)
            +
            (quote ? 2 : 0)
            +
            4;

        while (
            oi + needed >= cap
        )
        {
            cap *= 2;

            char *q =
                realloc(
                    out,
                    cap
                );

            if (!q)
            {
                free(value);
                free(abs);
                free(proxied);
                free(out);
                return NULL;
            }

            out = q;
        }

        memcpy(
            out + oi,
            attr,
            alen
        );

        oi += alen;

        out[oi++] = '=';

        if (quote)
            out[oi++] = quote;

        memcpy(
            out + oi,
            use,
            strlen(use)
        );

        oi += strlen(use);

        if (quote)
            out[oi++] = quote;

        if (
            quote &&
            p < inlen
        )
            p++;

        i = p;

        free(value);
        free(abs);
        free(proxied);
    }

    out[oi] = 0;

    return out;
}


static char *force_self_target(
    const char *html
)
{
    size_t n =
        strlen(html);

    size_t cap =
        n + 1024;

    char *out =
        strdup(html);

    if (!out)
        return NULL;

    char *p = out;

    while (
        (p =
            strcasestr(
                p,
                "target="
            ))
    )
    {
        char *v =
            p + 7;

        while (
            isspace(
                (unsigned char)*v
            )
        )
            v++;

        char quote = 0;

        if (
            *v == '"' ||
            *v == '\''
        )
        {
            quote = *v;
            v++;
        }

        char *e =
            quote
                ? strchr(v, quote)
                : v +
                    strcspn(
                        v,
                        " \t\r\n>"
                    );

        if (!e)
            break;

        size_t tail =
            strlen(e);

        size_t prefix =
            (size_t)(v - out);

        size_t newlen =
            prefix
            +
            5
            +
            tail
            +
            2;

        if (
            newlen >= cap
        )
        {
            cap =
                newlen + 1024;

            char *q =
                realloc(
                    out,
                    cap
                );

            if (!q)
            {
                free(out);
                return NULL;
            }

            p =
                q + prefix;

            out = q;

            v = p + 7;
            e =
                quote
                    ? strchr(
                        v,
                        quote
                    )
                    : v +
                        strcspn(
                            v,
                            " \t\r\n>"
                        );
        }

        memmove(
            v + 5,
            e,
            strlen(e) + 1
        );

        memcpy(
            v,
            "_self",
            5
        );

        p =
            v + 5;
    }

    return out;
}


static char *rewrite_html(
    const char *html,
    const char *target,
    const char *sid
)
{
    char *a =
        rewrite_attrs(
            html,
            target,
            sid
        );

    if (!a)
        return NULL;

    char *b =
        force_self_target(a);

    free(a);

    if (!b)
        return NULL;

    /*
     * Remove frame-blocking CSP meta tags.
     */
    for (;;)
    {
        char *m =
            strcasestr(
                b,
                "<meta"
            );

        if (!m)
            break;

        char *end =
            strchr(
                m,
                '>'
            );

        if (!end)
            break;

        size_t n =
            (size_t)(
                end - m
            ) + 1;

        char *tag =
            strndup(
                m,
                n
            );

        char *low =
            lowerdup(tag);

        int remove =
            low &&
            strstr(
                low,
                "content-security-policy"
            );

        free(tag);
        free(low);

        if (!remove)
        {
            b = end + 1;
            continue;
        }

        memmove(
            m,
            end + 1,
            strlen(end + 1) + 1
        );
    }

    /*
     * Early same-tab bridge.
     */
    const char *bridge_start =
        "<script>";

    const char *bridge_end =
        "</script>";

    size_t target_len =
        strlen(target);

    char *safe_target =
        malloc(
            target_len * 2 + 3
        );

    if (!safe_target)
        return b;

    char *q =
        safe_target;

    *q++ = '\'';

    for (
        const char *x =
            target;
        *x;
        x++
    )
    {
        if (
            *x == '\\' ||
            *x == '\''
        )
            *q++ = '\\';

        *q++ = *x;
    }

    *q++ = '\'';
    *q = 0;

    const char *js_fmt =
        "(function(){"
        "const SID='%s';"
        "const TARGET=%s;"
        "function P(u){"
        "try{"
        "const x=new URL(u,TARGET).href;"
        "const b=new TextEncoder().encode(x);"
        "let s='';"
        "for(let i=0;i<b.length;i++)"
        "s+=String.fromCharCode(b[i]);"
        "return '/proxy/'+SID+'/'+"
        "btoa(s).replace(/=/g,'')"
        ".replace(/\\\\+/g,'-')"
        ".replace(/\\\\//g,'_');"
        "}catch(e){return u}"
        "}"
        "window.open=function(u){"
        "if(u)location.href=P(u);"
        "return window;"
        "};"
        "document.addEventListener("
        "'click',function(e){"
        "const a=e.target.closest&&"
        "e.target.closest('a[href]');"
        "if(!a)return;"
        "a.target='_self';"
        "const u=a.href;"
        "if(/^https?:/i.test(u)){"
        "e.preventDefault();"
        "location.href=P(u);"
        "}"
        "},true);"
        "document.addEventListener("
        "'submit',function(e){"
        "const f=e.target;"
        "if(!f||!f.action)return;"
        "if(/^https?:/i.test(f.action)){"
        "e.preventDefault();"
        "const u=P(f.action);"
        "if((f.method||'GET').toUpperCase()==='GET'){"
        "location.href=u;"
        "}"
        "}"
        "},true);"
        "const F=window.fetch.bind(window);"
        "window.fetch=function(i,o){"
        "try{"
        "let u=typeof i==='string'?i:i.url;"
        "u=new URL(u,TARGET).href;"
        "if(/^https?:/i.test(u)){"
        "const p=P(u);"
        "if(typeof i==='string')i=p;"
        "else i=new Request(p,i);"
        "}"
        "}catch(e){}"
        "return F(i,o);"
        "};"
        "const X=window.XMLHttpRequest;"
        "window.XMLHttpRequest=function(){"
        "const x=new X();"
        "const op=x.open;"
        "x.open=function(m,u,a,b,c){"
        "try{"
        "u=P(new URL(u,TARGET).href);"
        "}catch(e){}"
        "return op.call(this,m,u,"
        "a,b,c);"
        "};"
        "return x;"
        "};"
        "const ps=history.pushState;"
        "const rs=history.replaceState;"
        "history.pushState=function(a,b,u){"
        "if(u)try{u=P(new URL(u,TARGET).href)}catch(e){}"
        "return ps.call(this,a,b,u);"
        "};"
        "history.replaceState=function(a,b,u){"
        "if(u)try{u=P(new URL(u,TARGET).href)}catch(e){}"
        "return rs.call(this,a,b,u);"
        "};"
        "})();";

    size_t js_len =
        strlen(js_fmt)
        +
        strlen(sid_placeholder)
        +
        strlen(safe_target)
        +
        128;

    free(safe_target);

    /*
     * Use a small dynamically generated bridge.
     */
    char *bridge =
        malloc(
            js_len
        );

    if (!bridge)
        return b;

    snprintf(
        bridge,
        js_len,
        js_fmt,
        sid,
        safe_target
    );

    size_t final_len =
        strlen(bridge_start)
        +
        strlen(bridge)
        +
        strlen(bridge_end)
        +
        strlen(b)
        +
        1;

    char *result =
        malloc(final_len);

    if (!result)
    {
        free(bridge);
        return b;
    }

    snprintf(
        result,
        final_len,
        "%s%s%s%s",
        bridge_start,
        bridge,
        bridge_end,
        b
    );

    free(bridge);
    free(b);

    return result;
}


/* =========================================================
   CURL FETCH
========================================================= */

typedef struct {
    Buffer body;

    HeaderNode *headers;

} FetchContext;


static size_t curl_write(
    void *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
)
{
    FetchContext *f =
        userdata;

    size_t n =
        size * nmemb;

    if (
        f->body.len + n >
        MAX_BODY
    )
        return 0;

    return
        buffer_append(
            &f->body,
            ptr,
            n
        )
        ? n
        : 0;
}


static size_t curl_header(
    char *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
)
{
    FetchContext *f =
        userdata;

    size_t n =
        size * nmemb;

    char *line =
        trimdup(
            ptr,
            n
        );

    if (!line)
        return n;

    if (
        !strncasecmp(
            line,
            "HTTP/",
            5
        )
    )
    {
        free(line);
        return n;
    }

    char *colon =
        strchr(
            line,
            ':'
        );

    if (!colon)
    {
        free(line);
        return n;
    }

    *colon = 0;

    char *name =
        trimdup(
            line,
            strlen(line)
        );

    char *value =
        trimdup(
            colon + 1,
            strlen(colon + 1)
        );

    if (
        name &&
        value
    )
    {
        add_header(
            &f->headers,
            name,
            value
        );
    }

    free(name);
    free(value);
    free(line);

    return n;
}


/* =========================================================
   REQUEST HEADER FORWARDING
========================================================= */

typedef struct {
    struct curl_slist *list;
} RequestHeaderContext;


static enum MHD_Result collect_request_header(
    void *cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *value
)
{
    if (
        kind != MHD_HEADER_KIND ||
        !key ||
        !value
    )
        return MHD_YES;

    RequestHeaderContext *ctx =
        cls;

    const char *blocked[] = {
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
        NULL
    };

    for (
        int i = 0;
        blocked[i];
        i++
    )
    {
        if (
            !strcasecmp(
                key,
                blocked[i]
            )
        )
            return MHD_YES;
    }

    char line[8192];

    int n =
        snprintf(
            line,
            sizeof(line),
            "%s: %s",
            key,
            value
        );

    if (
        n > 0 &&
        (size_t)n <
            sizeof(line)
    )
    {
        ctx->list =
            curl_slist_append(
                ctx->list,
                line
            );
    }

    return MHD_YES;
}


/* =========================================================
   TARGET RESPONSE
========================================================= */

typedef struct {

    long status;

    Buffer body;

    HeaderNode *headers;

} TargetResponse;


static void free_target_response(
    TargetResponse *r
)
{
    if (!r)
        return;

    buffer_free(
        &r->body
    );

    free_headers(
        r->headers
    );
}


/* =========================================================
   FETCH TARGET
========================================================= */

static int fetch_target(
    Session *session,
    const char *url,
    const char *method,
    const char *body,
    size_t body_len,
    struct MHD_Connection *connection,
    TargetResponse *out
)
{
    CURL *curl =
        curl_easy_init();

    if (!curl)
        return 0;

    FetchContext fc = {0};

    RequestHeaderContext rh = {0};

    MHD_get_connection_values(
        connection,
        MHD_HEADER_KIND,
        collect_request_header,
        &rh
    );

    char *cookies =
        cookie_header(
            session,
            url
        );

    if (cookies)
    {
        size_t n =
            strlen(cookies) + 10;

        char *line =
            malloc(n);

        if (line)
        {
            snprintf(
                line,
                n,
                "Cookie: %s",
                cookies
            );

            rh.list =
                curl_slist_append(
                    rh.list,
                    line
                );

            free(line);
        }
    }

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url
    );

    curl_easy_setopt(
        curl,
        CURLOPT_FOLLOWLOCATION,
        0L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HEADERFUNCTION,
        curl_header
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HEADERDATA,
        &fc
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        curl_write
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &fc
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        rh.list
    );

    /*
     * Browser's actual User-Agent,
     * Sec-CH-UA, Accept, language,
     * fetch metadata, Range, Origin,
     * Referer, etc. are forwarded.
     *
     * No hardcoded screen resolution.
     */
    curl_easy_setopt(
        curl,
        CURLOPT_ENCODING,
        ""
    );

    curl_easy_setopt(
        curl,
        CURLOPT_CONNECTTIMEOUT,
        20L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        90L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_SSL_VERIFYPEER,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_SSL_VERIFYHOST,
        2L
    );

    if (
        !strcasecmp(
            method,
            "HEAD"
        )
    )
    {
        curl_easy_setopt(
            curl,
            CURLOPT_NOBODY,
            1L
        );
    }
    else if (
        !strcasecmp(
            method,
            "POST"
        )
    )
    {
        curl_easy_setopt(
            curl,
            CURLOPT_POST,
            1L
        );

        curl_easy_setopt(
            curl,
            CURLOPT_POSTFIELDS,
            body
                ? body
                : ""
        );

        curl_easy_setopt(
            curl,
            CURLOPT_POSTFIELDSIZE,
            (long)body_len
        );
    }
    else if (
        strcasecmp(
            method,
            "GET"
        )
    )
    {
        curl_easy_setopt(
            curl,
            CURLOPT_CUSTOMREQUEST,
            method
        );

        curl_easy_setopt(
            curl,
            CURLOPT_POSTFIELDS,
            body
                ? body
                : ""
        );

        curl_easy_setopt(
            curl,
            CURLOPT_POSTFIELDSIZE,
            (long)body_len
        );
    }

    CURLcode rc =
        curl_easy_perform(
            curl
        );

    if (
        rc != CURLE_OK
    )
    {
        curl_slist_free_all(
            rh.list
        );

        free(cookies);

        buffer_free(
            &fc.body
        );

        free_headers(
            fc.headers
        );

        curl_easy_cleanup(
            curl
        );

        return 0;
    }

    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        &out->status
    );

    out->body =
        fc.body;

    out->headers =
        fc.headers;

    fc.body.data = NULL;
    fc.headers = NULL;

    /*
     * Save Set-Cookie into the
     * isolated session jar.
     */
    for (
        HeaderNode *h =
            out->headers;
        h;
        h = h->next
    )
    {
        if (
            !strcasecmp(
                h->name,
                "Set-Cookie"
            )
        )
        {
            store_cookie(
                session,
                h->value,
                url
            );
        }
    }

    curl_slist_free_all(
        rh.list
    );

    free(cookies);

    buffer_free(
        &fc.body
    );

    free_headers(
        fc.headers
    );

    curl_easy_cleanup(
        curl
    );

    return 1;
}


/* =========================================================
   DAILY LIMIT
========================================================= */

static int budget_allowed(
    Session *s
)
{
    time_t now =
        time(NULL);

    if (
        now -
        s->budget_day
        >=
        24 * 60 * 60
    )
    {
        s->budget_day = now;
        s->used_seconds = 0;
    }

    return
        s->used_seconds
        <
        DAILY_LIMIT_SECONDS;
}


/* =========================================================
   HTTP RESPONSE HELPERS
========================================================= */

static enum MHD_Result reply_text(
    struct MHD_Connection *c,
    unsigned status,
    const char *content_type,
    const char *text
)
{
    struct MHD_Response *r =
        MHD_create_response_from_buffer(
            strlen(text),
            (void *)text,
            MHD_RESPMEM_MUST_COPY
        );

    if (!r)
        return MHD_NO;

    MHD_add_response_header(
        r,
        "Content-Type",
        content_type
    );

    MHD_add_response_header(
        r,
        "Cache-Control",
        "no-store"
    );

    enum MHD_Result result =
        MHD_queue_response(
            c,
            status,
            r
        );

    MHD_destroy_response(r);

    return result;
}


static enum MHD_Result reply_json(
    struct MHD_Connection *c,
    const char *json
)
{
    return reply_text(
        c,
        200,
        "application/json; charset=utf-8",
        json
    );
}


/* =========================================================
   PROXY RESPONSE
========================================================= */

static enum MHD_Result proxy_response(
    struct MHD_Connection *connection,
    Session *session,
    const char *target,
    const char *method,
    const char *body,
    size_t body_len
)
{
    if (
        !budget_allowed(
            session
        )
    )
    {
        return reply_text(
            connection,
            429,
            "text/plain; charset=utf-8",
            "Daily proxy time limit reached."
        );
    }

    TargetResponse tr = {0};

    if (
        !fetch_target(
            session,
            target,
            method,
            body,
            body_len,
            connection,
            &tr
        )
    )
    {
        return reply_text(
            connection,
            502,
            "text/plain; charset=utf-8",
            "Proxy fetch failed."
        );
    }

    touch_session(session);

    /*
     * Upstream redirects NEVER escape to
     * the real website URL.
     */
    if (
        tr.status >= 300 &&
        tr.status < 400
    )
    {
        const char *location =
            get_header(
                tr.headers,
                "Location"
            );

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                0,
                NULL,
                MHD_RESPMEM_PERSISTENT
            );

        if (!r)
        {
            free_target_response(&tr);
            return MHD_NO;
        }

        if (location)
        {
            char *next =
                absolute_url(
                    target,
                    location
                );

            if (
                next &&
                is_http_url(next)
            )
            {
                char *p =
                    proxy_url(
                        next,
                        session->sid
                    );

                if (p)
                {
                    MHD_add_response_header(
                        r,
                        "Location",
                        p
                    );

                    free(p);
                }
            }

            free(next);
        }

        char cookie[256];

        snprintf(
            cookie,
            sizeof(cookie),
            "orbit_sid=%s; Path=/; HttpOnly; SameSite=Lax",
            session->sid
        );

        MHD_add_response_header(
            r,
            "Set-Cookie",
            cookie
        );

        enum MHD_Result result =
            MHD_queue_response(
                connection,
                (unsigned)tr.status,
                r
            );

        MHD_destroy_response(r);

        free_target_response(&tr);

        return result;
    }


    const char *content_type =
        get_header(
            tr.headers,
            "Content-Type"
        );

    if (!content_type)
        content_type =
            "application/octet-stream";


    Buffer output = tr.body;


    /*
     * Rewrite HTML only.
     */
    if (
        strstr(
            content_type,
            "text/html"
        )
        ||
        strstr(
            content_type,
            "application/xhtml"
        )
    )
    {
        if (
            output.len <= MAX_HTML
        )
        {
            char *html =
                malloc(
                    output.len + 1
                );

            if (html)
            {
                memcpy(
                    html,
                    output.data,
                    output.len
                );

                html[
                    output.len
                ] = 0;

                char *rewritten =
                    rewrite_html(
                        html,
                        target,
                        session->sid
                    );

                free(html);

                if (rewritten)
                {
                    buffer_free(
                        &output
                    );

                    output.data =
                        (unsigned char *)
                            rewritten;

                    output.len =
                        strlen(
                            rewritten
                        );

                    output.cap =
                        output.len + 1;
                }
            }
        }
    }


    struct MHD_Response *response =
        MHD_create_response_from_buffer(
            output.len,
            output.data,
            MHD_RESPMEM_MUST_COPY
        );

    if (!response)
    {
        buffer_free(&output);
        free_target_response(&tr);
        return MHD_NO;
    }


    MHD_add_response_header(
        response,
        "Content-Type",
        content_type
    );

    MHD_add_response_header(
        response,
        "Cache-Control",
        "private, no-store"
    );


    /*
     * Browser gets only the Orbit session cookie.
     * Target-site cookies stay server-side.
     */
    char session_cookie[256];

    snprintf(
        session_cookie,
        sizeof(session_cookie),
        "orbit_sid=%s; Path=/; HttpOnly; SameSite=Lax",
        session->sid
    );

    MHD_add_response_header(
        response,
        "Set-Cookie",
        session_cookie
    );


    for (
        HeaderNode *h =
            tr.headers;
        h;
        h = h->next
    )
    {
        if (
            !forward_header(
                h->name
            )
        )
            continue;


        if (
            !strcasecmp(
                h->name,
                "Content-Security-Policy"
            )
            ||
            !strcasecmp(
                h->name,
                "Content-Security-Policy-Report-Only"
            )
        )
        {
            char *safe =
                sanitize_csp(
                    h->value
                );

            if (safe)
            {
                MHD_add_response_header(
                    response,
                    h->name,
                    safe
                );

                free(safe);
            }

            continue;
        }


        MHD_add_response_header(
            response,
            h->name,
            h->value
        );
    }


    enum MHD_Result result =
        MHD_queue_response(
            connection,
            (unsigned)tr.status,
            response
        );

    MHD_destroy_response(
        response
    );

    buffer_free(
        &output
    );

    free_target_response(
        &tr
    );

    return result;
}


/* =========================================================
   QUERY
========================================================= */

static char *query_value(
    struct MHD_Connection *c,
    const char *name
)
{
    const char *v =
        MHD_lookup_connection_value(
            c,
            MHD_GET_ARGUMENT_KIND,
            name
        );

    return v
        ? strdup(v)
        : NULL;
}


/* =========================================================
   INJECTION STORE
========================================================= */

typedef struct Injection {

    char id[SID_LEN + 1];

    char *code;

    time_t created;

    struct Injection *next;

} Injection;


static pthread_mutex_t injection_lock =
    PTHREAD_MUTEX_INITIALIZER;

static Injection *injections = NULL;


static int store_injection(
    const char *id,
    char *code
)
{
    Injection *i =
        calloc(
            1,
            sizeof(*i)
        );

    if (!i)
        return 0;

    snprintf(
        i->id,
        sizeof(i->id),
        "%s",
        id
    );

    i->code =
        code;

    i->created =
        time(NULL);

    pthread_mutex_lock(
        &injection_lock
    );

    i->next =
        injections;

    injections =
        i;

    pthread_mutex_unlock(
        &injection_lock
    );

    return 1;
}


static char *get_injection(
    const char *id
)
{
    pthread_mutex_lock(
        &injection_lock
    );

    Injection **pp =
        &injections;

    while (*pp)
    {
        Injection *i =
            *pp;

        if (
            time(NULL) -
            i->created
            >
            INJECTION_TTL_SECONDS
        )
        {
            *pp =
                i->next;

            free(i->code);
            free(i);

            continue;
        }

        if (
            !strcmp(
                i->id,
                id
            )
        )
        {
            char *copy =
                strdup(
                    i->code
                );

            pthread_mutex_unlock(
                &injection_lock
            );

            return copy;
        }

        pp =
            &i->next;
    }

    pthread_mutex_unlock(
        &injection_lock
    );

    return NULL;
}


/* =========================================================
   ROUTING
========================================================= */

static int parse_proxy_path(
    const char *path,
    char **sid,
    char **target
)
{
    if (
        strncmp(
            path,
            "/proxy/",
            7
        )
    )
        return 0;

    const char *p =
        path + 7;

    const char *slash =
        strchr(
            p,
            '/'
        );

    if (!slash)
        return 0;

    size_t sid_len =
        (size_t)(
            slash - p
        );

    if (
        sid_len == 0 ||
        sid_len > SID_LEN
    )
        return 0;

    *sid =
        strndup(
            p,
            sid_len
        );

    *target =
        decode_url(
            slash + 1
        );

    return
        *sid &&
        *target;
}


/* =========================================================
   REQUEST BODY
========================================================= */

typedef struct {
    Buffer body;
} RequestContext;


/* =========================================================
   MAIN ROUTER
========================================================= */

static enum MHD_Result answer(
    void *cls,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls
)
{
    (void)cls;
    (void)version;

    RequestContext *ctx =
        *con_cls;

    if (!ctx)
    {
        ctx =
            calloc(
                1,
                sizeof(*ctx)
            );

        if (!ctx)
            return MHD_NO;

        *con_cls =
            ctx;
    }


    if (*upload_data_size)
    {
        if (
            ctx->body.len +
            *upload_data_size
            >
            MAX_BODY
        )
        {
            *upload_data_size = 0;

            return reply_text(
                connection,
                413,
                "text/plain; charset=utf-8",
                "Request body too large."
            );
        }

        buffer_append(
            &ctx->body,
            upload_data,
            *upload_data_size
        );

        *upload_data_size = 0;

        return MHD_YES;
    }


    /*
     * HOME
     */
    if (
        !strcmp(
            url,
            "/"
        )
    )
    {
        return reply_json(
            connection,
            "{"
            "\"name\":\"Orbit Source Proxy\","
            "\"status\":\"online\","
            "\"runtime\":\"C + libcurl + libmicrohttpd\","
            "\"navigationCooldown\":false,"
            "\"mobileMode\":\"forward-client-headers\","
            "\"accountCache\":\"session-cookie-jar\","
            "\"persistentCredentials\":false,"
            "\"dailyLimitSeconds\":600,"
            "\"features\":["
            "\"dynamic URL proxy\","
            "\"isolated sessions\","
            "\"isolated target cookies\","
            "\"HTML rewriting\","
            "\"same-tab navigation\","
            "\"popup blocking\","
            "\"target blank blocking\","
            "\"fetch bridge\","
            "\"XHR bridge\","
            "\"frame policy sanitization\","
            "\"browser cache compatibility\","
            "\"results compatibility\","
            "\"watch compatibility\","
            "\"Range forwarding\","
            "\"mobile header forwarding\""
            "]"
            "}"
        );
    }


    /*
     * SESSION STATUS
     */
    if (
        !strcmp(
            url,
            "/session/status"
        )
    )
    {
        return reply_json(
            connection,
            "{"
            "\"ok\":true,"
            "\"runtime\":\"c-proxy\""
            "}"
        );
    }


    /*
     * CACHE INFO
     */
    if (
        !strcmp(
            url,
            "/cache/info"
        )
    )
    {
        return reply_json(
            connection,
            "{"
            "\"browserCache\":true,"
            "\"serverCookieCache\":true,"
            "\"persistentCredentials\":false,"
            "\"note\":\"Target cookies are kept only in the active Orbit session.\""
            "}"
        );
    }


    /*
     * /inject
     */
    if (
        !strcmp(
            url,
            "/inject"
        )
        &&
        !strcasecmp(
            method,
            "POST"
        )
    )
    {
        if (
            !ctx->body.len
        )
        {
            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "No code supplied"
            );
        }

        if (
            ctx->body.len >
            MAX_INJECTION
        )
        {
            return reply_text(
                connection,
                413,
                "text/plain; charset=utf-8",
                "Injection code too large"
            );
        }

        char id[
            SID_LEN + 1
        ];

        random_sid(id);

        char *code =
            strndup(
                (char *)ctx->body.data,
                ctx->body.len
            );

        if (!code)
        {
            return reply_text(
                connection,
                500,
                "text/plain; charset=utf-8",
                "Allocation failed"
            );
        }

        if (
            !store_injection(
                id,
                code
            )
        )
        {
            free(code);

            return reply_text(
                connection,
                500,
                "text/plain; charset=utf-8",
                "Injection store failed"
            );
        }

        char json[256];

        snprintf(
            json,
            sizeof(json),
            "{"
            "\"id\":\"%s\","
            "\"script\":\"/inject/%s.js\""
            "}",
            id,
            id
        );

        return reply_json(
            connection,
            json
        );
    }


    /*
     * /inject/:id.js
     */
    if (
        !strncmp(
            url,
            "/inject/",
            8
        )
    )
    {
        const char *p =
            url + 8;

        const char *dot =
            strstr(
                p,
                ".js"
            );

        if (dot)
        {
            size_t n =
                (size_t)(
                    dot - p
                );

            if (
                n > 0 &&
                n <= SID_LEN
            )
            {
                char id[
                    SID_LEN + 1
                ];

                memcpy(
                    id,
                    p,
                    n
                );

                id[n] = 0;

                char *code =
                    get_injection(
                        id
                    );

                if (code)
                {
                    struct MHD_Response *r =
                        MHD_create_response_from_buffer(
                            strlen(code),
                            code,
                            MHD_RESPMEM_MUST_COPY
                        );

                    MHD_add_response_header(
                        r,
                        "Content-Type",
                        "application/javascript; charset=utf-8"
                    );

                    MHD_add_response_header(
                        r,
                        "Cache-Control",
                        "no-store"
                    );

                    enum MHD_Result result =
                        MHD_queue_response(
                            connection,
                            200,
                            r
                        );

                    MHD_destroy_response(r);

                    free(code);

                    return result;
                }
            }
        }

        return reply_text(
            connection,
            404,
            "text/plain; charset=utf-8",
            "// Not found"
        );
    }


    /*
     * CREATE SESSION + REDIRECT
     */
    if (
        !strcmp(
            url,
            "/open"
        )
        ||
        !strcmp(
            url,
            "/proxy"
        )
    )
    {
        char *target =
            query_value(
                connection,
                "url"
            );

        if (
            !target ||
            !is_http_url(target)
        )
        {
            free(target);

            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "Invalid HTTP(S) url"
            );
        }

        Session *session =
            create_session(
                target
            );

        if (!session)
        {
            free(target);

            return reply_text(
                connection,
                500,
                "text/plain; charset=utf-8",
                "Session creation failed"
            );
        }

        char *p =
            proxy_url(
                target,
                session->sid
            );

        free(target);

        if (!p)
            return reply_text(
                connection,
                500,
                "text/plain; charset=utf-8",
                "Proxy URL creation failed"
            );

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                0,
                NULL,
                MHD_RESPMEM_PERSISTENT
            );

        MHD_add_response_header(
            r,
            "Location",
            p
        );

        char cookie[256];

        snprintf(
            cookie,
            sizeof(cookie),
            "orbit_sid=%s; Path=/; HttpOnly; SameSite=Lax",
            session->sid
        );

        MHD_add_response_header(
            r,
            "Set-Cookie",
            cookie
        );

        enum MHD_Result result =
            MHD_queue_response(
                connection,
                302,
                r
            );

        MHD_destroy_response(r);

        free(p);

        return result;
    }


    /*
     * RAW SOURCE
     */
    if (
        !strcmp(
            url,
            "/source"
        )
    )
    {
        char *target =
            query_value(
                connection,
                "url"
            );

        if (
            !target ||
            !is_http_url(target)
        )
        {
            free(target);

            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "Invalid url"
            );
        }

        Session *session =
            create_session(
                target
            );

        TargetResponse tr = {0};

        int ok =
            fetch_target(
                session,
                target,
                method,
                (char *)ctx->body.data,
                ctx->body.len,
                connection,
                &tr
            );

        free(target);

        if (!ok)
        {
            free_target_response(
                &tr
            );

            return reply_text(
                connection,
                502,
                "text/plain; charset=utf-8",
                "Source fetch failed"
            );
        }

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                tr.body.len,
                tr.body.data,
                MHD_RESPMEM_MUST_COPY
            );

        MHD_add_response_header(
            r,
            "Content-Type",
            "text/plain; charset=utf-8"
        );

        enum MHD_Result result =
            MHD_queue_response(
                connection,
                (unsigned)tr.status,
                r
            );

        MHD_destroy_response(r);

        free_target_response(
            &tr
        );

        return result;
    }


    /*
     * FIND SESSION
     */
    char *sid = NULL;
    char *target = NULL;

    if (
        parse_proxy_path(
            url,
            &sid,
            &target
        )
    )
    {
        pthread_mutex_lock(
            &session_lock
        );

        Session *session =
            find_session(
                sid
            );

        pthread_mutex_unlock(
            &session_lock
        );

        if (
            !session
        )
        {
            free(sid);
            free(target);

            return reply_text(
                connection,
                404,
                "text/plain; charset=utf-8",
                "Proxy session expired"
            );
        }

        if (
            !is_http_url(
                target
            )
        )
        {
            free(sid);
            free(target);

            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "Only HTTP(S) URLs are supported"
            );
        }

        enum MHD_Result result =
            proxy_response(
                connection,
                session,
                target,
                method,
                (char *)ctx->body.data,
                ctx->body.len
            );

        free(sid);
        free(target);

        return result;
    }


    /*
     * /results
     *
     * Session is recovered from:
     * 1. sid query
     * 2. orbit_sid cookie
     * 3. Referer /proxy/SID/
     */
    if (
        !strcmp(
            url,
            "/results"
        )
        ||
        !strcmp(
            url,
            "/watch"
        )
    )
    {
        char *sidq =
            query_value(
                connection,
                "sid"
            );

        Session *session = NULL;

        pthread_mutex_lock(
            &session_lock
        );

        if (sidq)
            session =
                find_session(
                    sidq
                );

        if (!session)
        {
            const char *cookie =
                MHD_lookup_connection_value(
                    connection,
                    MHD_COOKIE_KIND,
                    "orbit_sid"
                );

            if (cookie)
                session =
                    find_session(
                        cookie
                    );
        }

        pthread_mutex_unlock(
            &session_lock
        );

        free(sidq);

        if (!session)
        {
            const char *referer =
                MHD_lookup_connection_value(
                    connection,
                    MHD_HEADER_KIND,
                    "Referer"
                );

            if (referer)
            {
                const char *p =
                    strstr(
                        referer,
                        "/proxy/"
                    );

                if (p)
                {
                    p += 7;

                    char tmp[
                        SID_LEN + 1
                    ];

                    size_t n = 0;

                    while (
                        *p &&
                        *p != '/' &&
                        n < SID_LEN
                    )
                    {
                        tmp[n++] =
                            *p++;
                    }

                    tmp[n] = 0;

                    pthread_mutex_lock(
                        &session_lock
                    );

                    session =
                        find_session(
                            tmp
                        );

                    pthread_mutex_unlock(
                        &session_lock
                    );
                }
            }
        }

        if (!session)
        {
            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "Missing proxy session"
            );
        }

        CURLU *u =
            curl_url();

        curl_url_set(
            u,
            CURLUPART_URL,
            session->origin,
            0
        );

        curl_url_set(
            u,
            CURLUPART_PATH,
            !strcmp(
                url,
                "/results"
            )
                ? "/results"
                : "/watch",
            0
        );

        char *query =
            NULL;

        const char *q =
            MHD_lookup_connection_value(
                connection,
                MHD_GET_ARGUMENT_KIND,
                "q"
            );

        if (q)
        {
            size_t n =
                strlen(q) + 3;

            query =
                malloc(n);

            if (query)
            {
                snprintf(
                    query,
                    n,
                    "q=%s",
                    q
                );

                curl_url_set(
                    u,
                    CURLUPART_QUERY,
                    query,
                    CURLU_URLENCODE
                );
            }
        }

        char *resolved =
            NULL;

        curl_url_get(
            u,
            CURLUPART_URL,
            &resolved,
            0
        );

        free(query);

        curl_url_cleanup(u);

        enum MHD_Result result =
            proxy_response(
                connection,
                session,
                resolved
                    ? resolved
                    : session->target,
                method,
                (char *)ctx->body.data,
                ctx->body.len
            );

        free(resolved);

        return result;
    }


    /*
     * EXTERNAL FETCH
     */
    if (
        !strcmp(
            url,
            "/__external"
        )
    )
    {
        char *sidq =
            query_value(
                connection,
                "sid"
            );

        char *external =
            query_value(
                connection,
                "url"
            );

        Session *session = NULL;

        pthread_mutex_lock(
            &session_lock
        );

        if (sidq)
            session =
                find_session(
                    sidq
                );

        if (!session)
        {
            const char *cookie =
                MHD_lookup_connection_value(
                    connection,
                    MHD_COOKIE_KIND,
                    "orbit_sid"
                );

            if (cookie)
                session =
                    find_session(
                        cookie
                    );
        }

        pthread_mutex_unlock(
            &session_lock
        );

        free(sidq);

        if (
            !session ||
            !external ||
            !is_http_url(
                external
            )
        )
        {
            free(external);

            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "Missing proxy session or invalid URL"
            );
        }

        enum MHD_Result result =
            proxy_response(
                connection,
                session,
                external,
                method,
                (char *)ctx->body.data,
                ctx->body.len
            );

        free(external);

        return result;
    }


    /*
     * DYNAMIC PATH
     */
    if (
        !strcmp(
            url,
            "/__path"
        )
    )
    {
        char *sidq =
            query_value(
                connection,
                "sid"
            );

        char *path =
            query_value(
                connection,
                "path"
            );

        Session *session = NULL;

        pthread_mutex_lock(
            &session_lock
        );

        if (sidq)
            session =
                find_session(
                    sidq
                );

        if (!session)
        {
            const char *cookie =
                MHD_lookup_connection_value(
                    connection,
                    MHD_COOKIE_KIND,
                    "orbit_sid"
                );

            if (cookie)
                session =
                    find_session(
                        cookie
                    );
        }

        pthread_mutex_unlock(
            &session_lock
        );

        free(sidq);

        if (
            !session ||
            !path ||
            path[0] != '/'
        )
        {
            free(path);

            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "Invalid path or session"
            );
        }

        CURLU *u =
            curl_url();

        curl_url_set(
            u,
            CURLUPART_URL,
            session->origin,
            0
        );

        curl_url_set(
            u,
            CURLUPART_PATH,
            path,
            0
        );

        char *resolved =
            NULL;

        curl_url_get(
            u,
            CURLUPART_URL,
            &resolved,
            0
        );

        curl_url_cleanup(u);

        enum MHD_Result result =
            proxy_response(
                connection,
                session,
                resolved
                    ? resolved
                    : session->target,
                method,
                (char *)ctx->body.data,
                ctx->body.len
            );

        free(resolved);
        free(path);

        return result;
    }


    /*
     * DYNAMIC NAVIGATION
     */
    if (
        !strcmp(
            url,
            "/__navigate"
        )
    )
    {
        char *sidq =
            query_value(
                connection,
                "sid"
            );

        char *destination =
            query_value(
                connection,
                "url"
            );

        Session *session = NULL;

        pthread_mutex_lock(
            &session_lock
        );

        if (sidq)
            session =
                find_session(
                    sidq
                );

        if (!session)
        {
            const char *cookie =
                MHD_lookup_connection_value(
                    connection,
                    MHD_COOKIE_KIND,
                    "orbit_sid"
                );

            if (cookie)
                session =
                    find_session(
                        cookie
                    );
        }

        pthread_mutex_unlock(
            &session_lock
        );

        free(sidq);

        if (
            !session ||
            !destination ||
            !is_http_url(
                destination
            )
        )
        {
            free(destination);

            return reply_text(
                connection,
                400,
                "text/plain; charset=utf-8",
                "Invalid navigation URL or session"
            );
        }

        char *origin =
            url_origin(
                destination
            );

        int allowed =
            origin &&
            session->origin &&
            !strcasecmp(
                origin,
                session->origin
            );

        free(origin);

        if (!allowed)
        {
            free(destination);

            return reply_text(
                connection,
                403,
                "text/plain; charset=utf-8",
                "Navigation target is outside the session"
            );
        }

        enum MHD_Result result =
            proxy_response(
                connection,
                session,
                destination,
                method,
                (char *)ctx->body.data,
                ctx->body.len
            );

        free(destination);

        return result;
    }


    return reply_text(
        connection,
        404,
        "text/plain; charset=utf-8",
        "Not found"
    );
}


/* =========================================================
   REQUEST CLEANUP
========================================================= */

static void request_completed(
    void *cls,
    struct MHD_Connection *connection,
    void **con_cls,
    enum MHD_RequestTerminationCode code
)
{
    (void)cls;
    (void)connection;
    (void)code;

    if (
        con_cls &&
        *con_cls
    )
    {
        RequestContext *ctx =
            *con_cls;

        buffer_free(
            &ctx->body
        );

        free(ctx);

        *con_cls = NULL;
    }
}


/* =========================================================
   CLEANUP THREAD
========================================================= */

static void cleanup_sessions(void)
{
    time_t now =
        time(NULL);

    pthread_mutex_lock(
        &session_lock
    );

    Session **pp =
        &sessions;

    while (*pp)
    {
        Session *s =
            *pp;

        if (
            now -
            s->last_used
            >
            SESSION_TTL_SECONDS
        )
        {
            *pp =
                s->next;

            free_session(s);

            continue;
        }

        pp =
            &s->next;
    }

    pthread_mutex_unlock(
        &session_lock
    );
}


static void cleanup_injections(void)
{
    time_t now =
        time(NULL);

    pthread_mutex_lock(
        &injection_lock
    );

    Injection **pp =
        &injections;

    while (*pp)
    {
        Injection *i =
            *pp;

        if (
            now -
            i->created
            >
            INJECTION_TTL_SECONDS
        )
        {
            *pp =
                i->next;

            free(i->code);
            free(i);

            continue;
        }

        pp =
            &i->next;
    }

    pthread_mutex_unlock(
        &injection_lock
    );
}


/* =========================================================
   MAIN
========================================================= */

int main(void)
{
    signal(
        SIGPIPE,
        SIG_IGN
    );

    curl_global_init(
        CURL_GLOBAL_DEFAULT
    );

    int port =
        DEFAULT_PORT;

    const char *env =
        getenv("PORT");

    if (
        env &&
        atoi(env) > 0
    )
    {
        port =
            atoi(env);
    }

    struct MHD_Daemon *daemon =
        MHD_start_daemon(
            MHD_USE_INTERNAL_POLLING_THREAD,
            port,

            MHD_OPTION_NOTIFY_COMPLETED,
            request_completed,
            NULL,

            MHD_OPTION_CONNECTION_TIMEOUT,
            120,

            MHD_OPTION_END
        );

    if (!daemon)
    {
        fprintf(
            stderr,
            "Failed to start Orbit C Proxy on port %d\n",
            port
        );

        curl_global_cleanup();

        return 1;
    }

    printf(
        "Orbit C Source Proxy running on 0.0.0.0:%d\n",
        port
    );

    fflush(stdout);


    while (1)
    {
        sleep(30);

        cleanup_sessions();
        cleanup_injections();
    }


    MHD_stop_daemon(
        daemon
    );

    curl_global_cleanup();

    return 0;
}
