/**
    Example certifcate code
    gcc -o certexample certexample.c -lssl -lcrypto
*/
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#define MINKEYSIZE 2048/8
#define WILDCARD_START 2
#define CA_CONSTRAINT "CA:FALSE"
#define WILDCARD "*."
#define WWW "www."
#define TLS "TLS Web Server Authentication"

char* ext_data(X509_EXTENSION *extension);
char* get_extension_data(const STACK_OF(X509_EXTENSION) *ext_list, 
                    X509 *cert, int NID);
bool check_name(X509* cert, char *website);
bool check_wildcard(char *domain_cn, char* website);
bool valid_wildcard(char *domain_cn);
bool check_www(char* website);
bool check_subject_alt(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert);

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr,"ERROR, no path provided\n");
        exit(1);
    }
    char *filepath = argv[1];

    FILE *input;
    FILE *output;
    input = fopen(filepath, "r");
    output = fopen("output.csv", "w");
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    char *test_cert_example;
   
    char correct = '0';

    //const char test_cert_example[] = "./cert-file2.pem";
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    while ((read = getline(&line, &len, input)) != -1) {
       
        char *original = malloc(strlen(line));
        strcpy(original, line);

        char *website_nl;
        char *type_delimitter = ",";
        strtok_r(line, type_delimitter, &website_nl);

        // get rid of new line
        char *website = strtok(website_nl, "\r\n");
        test_cert_example = malloc(strlen(line));
        strcpy(test_cert_example, line);
        //printf("%s\n", line);

        fputs(original, output);
    

        //create BIO object to read certificate
        certificate_bio = BIO_new(BIO_s_file());

        //Read certificate into BIO
        if (!(BIO_read_filename(certificate_bio, test_cert_example)))
        {
            fprintf(stderr, "Error in reading cert BIO filename");
            exit(EXIT_FAILURE);
        }
        if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
        {
            fprintf(stderr, "Error in loading certificate");
            exit(EXIT_FAILURE);
        }

        //cert contains the x509 certificate and can be used to analyse the certificate

        // get certificate extensions
        cert_inf = cert->cert_info;
        ext_list = cert_inf->extensions;

        // current time 
        time_t rawtime;    
        time(&rawtime);
        localtime (&rawtime);
        ASN1_TIME *current = NULL;
        ASN1_TIME_set(current, rawtime);

        // get before
        ASN1_TIME *before_time = X509_get_notBefore(cert);
        
        // get after
        ASN1_TIME *after_time = X509_get_notAfter(cert);

        // check before time
        int pday, psec;
        ASN1_TIME_diff(&pday, &psec, before_time, current);
        if(pday > 0 || psec > 0){
            printf("Before: FINE\n");
        } else {
            printf("Before: not fine\n");
        }

        // check after time
        ASN1_TIME_diff(&pday, &psec, current, after_time);
        if(pday > 0 || psec > 0){
            printf("After: FINE\n");
        } else {
            printf("After: not fine\n");
        }

        if(!check_name(cert, website)){
           // check_subject_alt();
            // Get subject alternative name data
            //char *extension_data = get_extension_data(ext_list, cert, NID_subject_alt_name);
            
            //printf("%s\n", extension_data);
        }

        // https://stackoverflow.com/questions/27327365/openssl-how-to-find-out-what
        // -the-bit-size-of-the-public-key-in-an-x509-certifica
        // Get key size
        EVP_PKEY *cert_key = X509_get_pubkey(cert);
        RSA *rsa = EVP_PKEY_get1_RSA(cert_key);
        int key_length = RSA_size(rsa);
        if(key_length >= MINKEYSIZE){
            printf("Key size is fine\n");
        } else {
            printf("Key size is not fine\n");
        }
        RSA_free(rsa);


        // get extension flags for basic constraints 
       
        char *extension_data = get_extension_data(ext_list, cert, NID_basic_constraints);
        printf("%s\n", extension_data);



        // Get enhanced key usage data
        extension_data = get_extension_data(ext_list, cert, NID_ext_key_usage);
        printf("%s\n", extension_data);
        if(strstr(extension_data, TLS)){
            printf("Contains TLS WEB Server authentication\n");
        } else {
            printf("Doesn't have tls\n");
        }

        
        //*********************
        // End of Example code
        //*********************
        X509_free(cert);
        BIO_free_all(certificate_bio);
        printf("\n\n\n");
        
        break;
        
    }
    fclose(input);
    fclose(output);
    
    exit(0);
}

bool 
check_subject_alt(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert) {
    //char *extension_data = get_extension_data(ext_list, cert, NID_subject_alt_name);
            
    //printf("%s\n", extension_data);
}


bool
check_name(X509 *cert, char* website){
        // get common name 
        X509_NAME *common_name = NULL;
        common_name = X509_get_subject_name(cert);
        char domain_cn[256] = "Domain CN NOT FOUND";
        X509_NAME_get_text_by_NID(common_name, NID_commonName, domain_cn, 256);
        bool valid = false;
        if(strcmp(domain_cn, website)==0){
            valid = true;
        } else {
            valid = check_wildcard(domain_cn, website);
            
        }
        return valid;
}
bool
check_wildcard(char *domain_cn, char *website){
    
    if(valid_wildcard(domain_cn)){

        // chop off the first two characters to get the website without *.
        char *domain_copy = malloc(strlen(domain_cn));
        strcpy(domain_copy, domain_cn);
        domain_copy+=WILDCARD_START;


        char *website_copy = malloc(strlen(website));
        strcpy(website_copy, website);
        

        // remove WWW if it has it
        if(check_www(website)){
            website_copy+=strlen(WWW);
        }
        
        if(strcmp(domain_copy, website_copy)==0){
            printf("Matches wildcard\n" );
            return true;
        }              
    }
    return false;
}

bool
check_www(char* website){
    char *checker = (char*) malloc(sizeof(char) * strlen(WWW)+1);
    strncpy(checker, website, strlen(WWW));
    checker[strlen(WWW)] = '\0';
    if(strcmp(checker, WWW)==0){
        printf("IT HAS WWW.\n" );
        return true;
    }
    return false;
}

bool 
valid_wildcard(char *domain_cn){
    char *checker = (char*) malloc(sizeof(char) * WILDCARD_START+1);
    strncpy(checker, domain_cn, 2);
    checker[WILDCARD_START] = '\0';
    if(strcmp(checker, WILDCARD)==0){
        return true;
    }
    return false;
}

char *
get_extension_data(const STACK_OF(X509_EXTENSION) *ext_list, 
                    X509 *cert, int NID) {

    int exists = X509v3_get_ext_by_NID(ext_list, NID, -1);
    char* extension_data=NULL;    
    if(exists!=-1){


        X509_EXTENSION *basic = X509_get_ext(cert, exists);
        ASN1_OBJECT *basic_obj = X509_EXTENSION_get_object(basic);
        char basic_buff[1024]; 
        OBJ_obj2txt(basic_buff, 1024, basic_obj, 0);
        printf("Extension = %s\n", basic_buff);
        extension_data = ext_data(basic);
    
    }
    return extension_data;

}

char *
ext_data(X509_EXTENSION *extension) {

        BUF_MEM *bptr = NULL;
        char *buf = NULL;
        BIO *bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(bio, extension, 0, 0))
        {
            fprintf(stderr, "Error in reading extensions");
        } 
        

        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bptr);
        
        
        //bptr->data is not NULL terminated - add null character
        buf = (char *)malloc((bptr->length + 1) * sizeof(char));
        memcpy(buf, bptr->data, bptr->length);
        buf[bptr->length] = '\0';
        
        BIO_free_all(bio);
        return buf;
}