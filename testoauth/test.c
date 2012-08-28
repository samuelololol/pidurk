#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

typedef struct {
    const char *uri;
    const char *access;
    const char *request;
    char *c_key;
    char *c_secret;
    char *t_key;
    char *t_secret;
}plurk_login_info;

inline static char* s_concate(const char** p1, const char** p2)
{
    int length = strlen(*p1) + strlen(*p2);
    char* newstring = malloc(sizeof(char) * (length + 1));
    memset(newstring, 0, length + 1);

    newstring = strncpy(newstring, *p1, strlen(*p1));
    newstring = strncat(newstring, *p2, strlen(*p2));
    return newstring;
}

void request_token_example_post(plurk_login_info *p) {
    char *request_token_uri = s_concate(&(p->uri), &(p->request));
    const char *req_c_key = p->c_key;
    const char *req_c_secret = p->c_secret;
    char **res_t_key = &(p->t_key);              
    char **res_t_secret = &(p->t_secret);        

    char *postarg = NULL;
    char *req_url;
    char *reply;

    req_url = oauth_sign_url2(
              request_token_uri,  // url
              &postarg,           // postarg
              OA_HMAC,            // OAuthMethod
              "POST",             // HTTPMethod
              req_c_key,          // customer key
              req_c_secret,       // customer secret
              NULL,               // token key
              NULL);              // token secret

    reply = oauth_http_post(req_url,postarg);
    if (!reply)
        printf("HTTP request for an oauth request-token failed.\n");
    else {
        int rc;
        char **rv = NULL;
        //printf("HTTP-reply: %s\n", reply);
        rc = oauth_split_url_parameters(reply, &rv);
        qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
        if( rc>=3
                && !strncmp(rv[2],"oauth_token_secret=",18) 
                && !strncmp(rv[1],"oauth_token=",11)
          ){
            *res_t_key=strdup(&(rv[1][12]));
            *res_t_secret=strdup(&(rv[2][19]));
#if SAMUEL_DEBUG
            printf("key: '%s'\nsecret: '%s'\n",*res_t_key, *res_t_secret);
#endif
        }
        if(rv) free(rv);
    }
    if(reply) free(reply);
    if(req_url) free(req_url);
    if(postarg) free(postarg);
    if(request_token_uri) free(request_token_uri);
}

void access_token_example_get(plurk_login_info *p, char a[]) {
    char *request_token_uri = s_concate(&(p->uri), &(p->access));
    const char *req_c_key = p->c_key;
    const char *req_c_secret = p->c_secret;
    //const char *res_t_key = p->t_key;              
    //const char *res_t_secret = p->t_secret;        
    char **res_t_key = &(p->t_key);              
    char **res_t_secret = &(p->t_secret);        

    char *postarg = NULL;
    char *req_url;
    char *reply;

    int verifier_len = strlen(a);
    char *verifier = malloc(sizeof(char)*(15 + verifier_len + 1));
    memset(verifier, 0, 15 + verifier_len + 1);
    verifier = memcpy(verifier, "oauth_verifier=", 15);
    verifier = strncat(verifier, a, verifier_len);

    //req_url = oauth_sign_url2(request_token_uri, // const char *url
    //        &postarg,                            // char **postarg 
    //        OA_HMAC,                             // OAuthMethod method
    //        "POST",                              // const char *http_method
    //        req_c_key,                           // const char *c_key
    //        req_c_secret,                        // const char *c_secret
    //        res_t_key,                        // const char *t_key
    //        res_t_secret                        // char *t_secret
    //        );
    
    // transfer oauth_sign_url2() in steps
    // example edited from: 
    // http://liboauth.sourceforge.net/tests_2oauthtest2_8c-example.html#a0
    int argc=0;
    char **argv=NULL;
    char *req_hdr = NULL;
    char *http_hdr= NULL;

    argc = oauth_split_url_parameters(request_token_uri, &argv);
#if SAMUEL_DEBUG
    if (1) {
        int i;
        for (i=0;i<argc; i++)
            printf("samuel, before add:\n%d:%s\n", i, argv[i]);
    }
#endif

    // the most important step here!!
    oauth_add_param_to_array(&argc, &argv, verifier);

#if SAMUEL_DEBUG
    if (1) {
        int i;
        for (i=0;i<argc; i++)
            printf("samuel, after add:\n%d:%s\n", i, argv[i]);
    }
#endif


    oauth_sign_array2_process(&argc, &argv,
            NULL, //< postargs (unused)
            OA_HMAC,
            "GET", //< HTTP method (defaults to "GET")
            req_c_key, req_c_secret,//NULL, NULL);
            *res_t_key, *res_t_secret);

    req_hdr = oauth_serialize_url_sep(argc, 1, argv, ", ", 6);
    req_url = oauth_serialize_url_sep(argc, 0, argv, "&", 1);
    oauth_free_array(&argc, &argv);
#if SAMUEL_DEBUG
    printf("samuel, req_hdr: %s\n",req_hdr);
    printf("samuel, req_url: %s\n",req_url);
#endif
    http_hdr = malloc(strlen(req_hdr) + 100);
    memset(http_hdr,0,100);
    sprintf(http_hdr, "Authorization: OAuth realm=\"\", %s", req_hdr);
#if SAMUEL_DEBUG
    printf("request URL=%s\n", req_url);
    printf("request header=%s\n\n", http_hdr);
#endif

    //reply = oauth_http_post2(req_url,postarg,http_hdr);
    reply = oauth_http_get2(req_url,postarg,http_hdr);

    if(!reply)
        printf("samuel, QQ>>>  HTTP request for an oauth request-token failed.\n");
    else {
        int rc;
        char **rv=NULL;
        printf("samuel, access_token HTTP-reply: %s\n", reply);
        rc = oauth_split_url_parameters(reply, &rv);
        printf("samuel, access_toekn rc: %d\n",rc);
        qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
        printf("samuel, access_token rv: %s\n", *rv);

        //if( rc==2 
        //        && !strncmp(rv[0],"oauth_token=",11)
        //        && !strncmp(rv[1],"oauth_token_secret=",18) ){
        //    res_t_key=strdup(&(rv[0][12]));
        //    res_t_secret=strdup(&(rv[1][19]));
        //    printf("key:    '%s'\nsecret: '%s'\n",res_t_key, res_t_secret);

        //}
        if(rv) free(rv);
    }

    if(http_hdr) free(http_hdr);
    if(req_hdr) free(req_hdr);
    if(verifier) free(verifier);
    if(reply) free(reply);
    if(req_url) free(req_url);
    if(postarg) free(postarg);
    if(request_token_uri) free(request_token_uri);
}

int main (int argc, char **argv) {
    plurk_login_info p;
    char authnum[8]={};

    p.uri = "http://www.plurk.com/OAuth/";
    p.request = "request_token";
    p.access = "access_token";

    p.c_key = strndup(argv[1],strlen(argv[1]));
    p.c_secret = strndup(argv[2],strlen(argv[2]));

#if SAMUEL_DEBUG 
    printf("sssssssamuel pkey: %s\n",p.c_key);
    printf("sssssssamuel psecert: %s\n",p.c_secret);
    printf(" *** sending HTTP request *** \n\n");
#endif
    request_token_example_post(&p);


#if SAMUEL_DEBUG 
    printf("t_key: %s\tt_secret: %s\n",p.t_key,p.t_secret);
#endif
    printf("http://www.plurk.com/OAuth/authorize?oauth_token=%s\n",p.t_key);
    printf("Authorize the access to your Plurk account: \n");
    scanf("%s",authnum);
    access_token_example_get(&p,authnum);
    return 0;
}
//vim:fdm=marker
