#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

#define DEBUG 0

typedef struct {
    const char *uri;
    const char *c_key;
    const char *c_secret;
    const char *t_key;
    const char *t_secret;
}plurk_login_info;


void request_token_example_post( plurk_login_info *p) {
    const char *request_token_uri = p->uri;
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
    const char *request_token_uri = p->uri;
    const char *req_c_key = p->c_key;
    const char *req_c_secret = p->c_secret;
    const char **res_t_key = &(p->t_key);              
    const char **res_t_secret = &(p->t_secret);        

    char *postarg = NULL;
    //char *postarg = strncat("oauth_verifier=",*a,strlen(*a));
    char *req_url;
    char *reply;

    a = strncat(a,"oauth_verifier=", 16 + strlen(a));

    req_url = oauth_sign_url2(request_token_uri, 
            &postarg, 
            OA_HMAC, 
            "POST",
            req_c_key, 
            req_c_secret, 
            NULL, 
            NULL);

    //oauth_sign_url2 (const char *url, 
    //                 char **postarg, 
    //                 OAuthMethod method, 
    //                 const char *http_method, 
    //                 const char *c_key, 
    //                 const char *c_secret, 
    //                 const char *t_key, 
    //                 const char *t_secret)
    //
    int verifier_len = strlen(a);
    char *verifier = malloc(sizeof(char)*(16 + verifier_len + 1));
    memset(verifier,'\0',16 + verifier_len + 1);
    verifier = strncpy(verifier,"&oauth_verifier=",16);
    verifier = strncat(verifier, a, 16 + verifier_len + 1);
    printf("%s \n",verifier);

    int newp_len = (verifier_len + strlen(postarg));
    char *newp = malloc(sizeof(char) * newp_len + 1);
    memset(newp,'\0', newp_len + 1);
    newp = strncpy(newp, postarg , strlen(postarg));
    newp = strncat(newp, verifier, verifier_len);

    free(verifier);
    free(postarg);
    postarg = newp;



    printf(">> %s\n",postarg);
    printf("<<\n");



#ifdef DEBUG
    printf("request URL:%s\n\n", req_url);
#endif
    reply = oauth_http_post(req_url,postarg);
    if (!reply)
#ifdef DEBUG
        printf("HTTP request for an oauth request-token failed.\n");
#endif
    else {
        int rc;
        char **rv = NULL;
#ifdef DEBUG
        printf("HTTP-reply: %s\n", reply);
#endif
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
int main (int argc, char **argv) {
    plurk_login_info p;
    p.uri = "http://www.plurk.com/OAuth/request_token";
    p.c_key = "CqjHQlKFxo4c";
    p.c_secret = "96OcDCQqXpjbNsgEpAgeO5EptBGRr89g";

    printf(" *** sending HTTP request *** \n\n");
    request_token_example_post(&p);
#ifdef DEBUG
    printf("t_key: %s\tt_secret: %s\n",p.t_key,p.t_secret);
#endif
    printf("Authorize the access to your Plurk account: \n");
    printf("http://www.plurk.com/OAuth/authorize?oauth_token=%s\n",p.t_key);
    char authnum[128]={};
    scanf("%s",authnum);
    printf("enter the Authorize number:");
    access_token_example_post(&p,authnum);
    return 0;
}
//vim:fdm=marker
