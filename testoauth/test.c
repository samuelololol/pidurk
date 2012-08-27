#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

#define DEBUG 0

typedef struct {
    const char *uri;
    const char *access;
    const char *request;
    char *c_key;
    char *c_secret;
    const char *t_key;
    const char *t_secret;
}plurk_login_info;


void request_token_example_post( plurk_login_info *p) {
    int uri_len = strlen(p->uri) + strlen(p->request);
    char *request_token_uri = malloc(sizeof(char)*(uri_len+1));
    memset(request_token_uri,0,uri_len + 1);
    request_token_uri = strncpy(request_token_uri,p->uri,strlen(p->uri));
    request_token_uri = strncat(request_token_uri,p->request,strlen(p->request));
    const char *req_c_key = p->c_key;
    const char *req_c_secret = p->c_secret;
    const char **res_t_key = &(p->t_key);              
    const char **res_t_secret = &(p->t_secret);        

    char *postarg = NULL;
    //char *postarg = strncat("oauth_verifier=",a,strlen(a));
    //char *postarg = malloc(sizeof(char)*(15+strlen(a)+1));
    char *req_url;
    char *reply;

    req_url = oauth_sign_url2(request_token_uri, 
            &postarg, 
            OA_HMAC, 
            "POST", 
            req_c_key, 
            req_c_secret, 
            NULL, 
            NULL);
    
    printf("samuel, get the request key: postarg: \n%s\n", postarg);
    printf("samuel, request key, req_url: %s\n", req_url);

    //oauth_sign_url2 (const char *url, 
    //                 char **postarg, 
    //                 OAuthMethod method, 
    //                 const char *http_method, 
    //                 const char *c_key, 
    //                 const char *c_secret, 
    //                 const char *t_key, 
    //                 const char *t_secret)


    printf("request URL:%s\n\n", req_url);
    reply = oauth_http_post(req_url,postarg);
    if (!reply)
        printf("HTTP request for an oauth request-token failed.\n");
    else {
        int rc;
        char **rv = NULL;
        printf("HTTP-reply: %s\n", reply);
        rc = oauth_split_url_parameters(reply, &rv);
        qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
        if( rc>=3
                && !strncmp(rv[2],"oauth_token_secret=",18) 
                && !strncmp(rv[1],"oauth_token=",11)
          ){
            *res_t_key=strdup(&(rv[1][12]));
            *res_t_secret=strdup(&(rv[2][19]));
#ifdef DEBUG
            printf("key: '%s'\nsecret: '%s'\n",*res_t_key, *res_t_secret);
#endif
        }
        if(rv) free(rv);
    }
    if(req_url) free(req_url);
    if(postarg) free(postarg);
    if(reply) free(reply);
}

void access_token_example_post(plurk_login_info *p, char a[]) {
    int uri_len = strlen(p->uri) + strlen(p->access);
    char *request_token_uri = malloc(sizeof(char)*(uri_len+1));
    memset(request_token_uri,0,uri_len + 1);
    request_token_uri = strncpy(request_token_uri,p->uri,strlen(p->uri));
    request_token_uri = strncat(request_token_uri,p->access,strlen(p->access));
    const char *req_c_key = p->c_key;
    const char *req_c_secret = p->c_secret;
    const char *res_t_key = p->t_key;              
    const char *res_t_secret = p->t_secret;        

    char *postarg = NULL;
    char *req_url;
    char *reply;

    int otoken_len = strlen(p->t_key);
    int otokens_len = strlen(p->t_secret);
    int verifier_len = strlen(a);

    char *otoken = malloc(sizeof(char)*(12 + otoken_len +1));
    memset(otoken, 0, 12 + otoken_len + 1);
    otoken = memcpy(otoken, "oauth_token=", 12);
    otoken = strncat(otoken, p->t_key, otoken_len);

    char *otokens = malloc(sizeof(char)*(19 + otokens_len +1));
    memset(otokens, 0, 19 + otokens_len + 1);
    otokens = memcpy(otokens, "oauth_token_secret=", 19);
    otokens = strncat(otokens, p->t_secret, otokens_len);

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
    
    // oauth_sign_url2 in steps
    // example edited from: 
    // http://liboauth.sourceforge.net/tests_2oauthtest2_8c-example.html#a0
    int argc;
    char **argv=NULL;
    char *req_hdr = NULL;
    char *http_hdr= NULL;

    argc = oauth_split_url_parameters(request_token_uri, &argv);
    if (1) {
        int i;
        for (i=0;i<argc; i++)
            printf("%d:%s\n", i, argv[i]);
    }

    // the most important step here!!
    oauth_add_param_to_array(&argc, &argv, otoken);
    oauth_add_param_to_array(&argc, &argv, otokens);
    oauth_add_param_to_array(&argc, &argv, verifier);

    if (1) {
        int i;
        for (i=0;i<argc; i++)
            printf("%d:%s\n", i, argv[i]);
    }


    oauth_sign_array2_process(&argc, &argv,
            NULL, //< postargs (unused)
            OA_HMAC,
            "GET", //< HTTP method (defaults to "GET")
            req_c_key, req_c_secret, NULL, NULL);

    req_hdr = oauth_serialize_url_sep(argc, 1, argv, ", ", 6);
    req_url = oauth_serialize_url_sep(argc, 0, argv, "&", 1);
    oauth_free_array(&argc, &argv);
    printf("samuel, req_hdr: %s\n",req_hdr);
    memset(req_url+strlen(req_url)-1,'\0',1);
    printf("samuel, req_url: %s\n",req_url);



    http_hdr = malloc(strlen(req_hdr) + 100);
    memset(http_hdr,0,100);
    sprintf(http_hdr, "Authorization: OAuth realm=\"http://www.plurk.com\", %s", req_hdr);
    //sprintf(http_hdr, "Authorization: OAuth , %s", req_hdr);
    //sprintf(http_hdr, "Authorization: OAuth realm=\"http://www.plurk.com/OAuth/access_token\", %s", req_hdr);
    printf("request URL=%s\n", req_url);
    printf("request header=%s\n\n", http_hdr);

    //reply = oauth_http_post2(req_url,postarg,http_hdr);
    reply = oauth_http_get2(req_url,postarg,http_hdr);
    printf("samuel, access postarg: %s\n", postarg);

    if(!reply)
        printf("samuel, QQ>>>  HTTP request for an oauth request-token failed.\n");
    else {
        int rc;
        char **rv=NULL;
        printf("samuel, HTTP-reply: %s\n", reply);
        rc = oauth_split_url_parameters(reply, &rv);
        printf("samuel, rc: %d\n",rc);
        qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
        printf("samuel, rv: %s\n", *rv);

        //if( rc==2 
        //        && !strncmp(rv[0],"oauth_token=",11)
        //        && !strncmp(rv[1],"oauth_token_secret=",18) ){
        //    res_t_key=strdup(&(rv[0][12]));
        //    res_t_secret=strdup(&(rv[1][19]));
        //    printf("key:    '%s'\nsecret: '%s'\n",res_t_key, res_t_secret);

        //}
        //if(rv) free(rv);
    }
}



int main (int argc, char **argv) {
    plurk_login_info p;
    p.uri = "http://www.plurk.com/OAuth/";
    p.request = "request_token";
    p.access = "access_token";

    p.c_key = malloc(sizeof(char)*(strlen(argv[1]))+1);
    p.c_secret = malloc(sizeof(char)*(strlen(argv[2]))+1);
    memset(p.c_key,0,strlen(argv[1])+1);
    memset(p.c_secret,0,strlen(argv[2])+1);
    
    p.c_key = memcpy(p.c_key,argv[1],strlen(argv[1]));
    memset(p.c_key+strlen(argv[1])+1,'\0',1);
    p.c_secret = memcpy(p.c_secret,argv[2],strlen(argv[2]));
    memset(p.c_secret+strlen(argv[2])+1,'\0',1);

    printf("sssssssamuel pkey: %s\n",p.c_key);
    printf("psecert: %s\n",p.c_secret);

    printf(" *** sending HTTP request *** \n\n");
    request_token_example_post(&p);
#ifdef DEBUG
    printf("t_key: %s\tt_secret: %s\n",p.t_key,p.t_secret);
#endif
    printf("http://www.plurk.com/OAuth/authorize?oauth_token=%s\n",p.t_key);
    printf("Authorize the access to your Plurk account: \n");
    char authnum[128]={};
    scanf("%s",authnum);
    printf("enter the Authorize number:\n");
    access_token_example_post(&p,authnum);
    return 0;
}
//vim:fdm=marker
