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
#define DNS "DNS:"
#define TLS "TLS Web Server Authentication"
#define VALID ",1\r\n"
#define INVAlID ",0\r\n"



char* ext_data(X509_EXTENSION *extension);
char* get_extension_data(const STACK_OF(X509_EXTENSION) *ext_list, 
                    X509 *cert, int NID);
bool check_time(X509 *cert);
bool check_common_name(X509* cert, char *website);
bool check_basic_constraints(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert);
bool check_wildcard(char *domain_cn, char* website);
bool check_name(char *name, char *website);
bool check_key(X509 *cert);
bool valid_time(ASN1_TIME *cert_time, ASN1_TIME *current_time);
bool check_containing(char *extension_data, char *constraint);
bool valid_wildcard(char *domain_cn);
bool check_subject_alt(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert, char *website);
bool check_overall_name(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert, char *website);
bool check_extended_key(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert);

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
   
    char *result;

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


        result = INVAlID;
        char *original_nl = malloc(strlen(line));
        strcpy(original_nl, line);

        char *website_nl;
        char *type_delimitter = ",";
        strtok_r(line, type_delimitter, &website_nl);

        // get rid of new line
        char *website = strtok(website_nl, "\r\n");
        test_cert_example = malloc(strlen(line));
        strcpy(test_cert_example, line);
        //printf("%s\n", line);

       
    

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

        // get certificate extensions and info
        cert_inf = cert->cert_info;
        ext_list = cert_inf->extensions;

        
        bool valid_name = check_overall_name(ext_list, cert, website);
       
        
        bool valid_time = check_time(cert);
       
        bool valid_key = check_key(cert);
       


        


        // get extension flags for basic constraints 
        bool valid_basic = check_basic_constraints(ext_list, cert);
       
        

        // Get enhanced key usage data
        bool valid_extended_key = check_extended_key(ext_list, cert);
      
        if (valid_name && valid_time &&valid_key && valid_basic && valid_extended_key){
            result = VALID;
        }
        
        // get rid of new line from original
        char *original =strtok(original_nl, "\r\n");
        char *output_line = malloc(strlen(original)+strlen(result)+1); // one extra for null byte
        strcpy(output_line, original);
        strcat(output_line, result);
        fputs(output_line, output);
       
        //*********************
        // End of Example code
        //*********************
        X509_free(cert);
        BIO_free_all(certificate_bio);
        
        
        
        
    }
    fclose(input);
    fclose(output);
    
    exit(0);
}

bool
check_extended_key(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert){
    char *extension_data = get_extension_data(ext_list, cert, NID_ext_key_usage);
    return check_containing(extension_data, TLS);
}

bool 
check_basic_constraints(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert){
    char *extension_data = get_extension_data(ext_list, cert, NID_basic_constraints);
    return check_containing(extension_data, CA_CONSTRAINT);
    
}

bool
check_containing(char *extension_data, char *constraint){
    if(strstr(extension_data, constraint)){
        return true;
    } 
    return false;
}
bool 
check_key(X509 *cert){

    // https://stackoverflow.com/questions/27327365/openssl-how-to-find-out-what
    // -the-bit-size-of-the-public-key-in-an-x509-certifica

    // Get key size
    bool valid_key = false;
    EVP_PKEY *cert_key = X509_get_pubkey(cert);
    RSA *rsa = EVP_PKEY_get1_RSA(cert_key);
    int key_length = RSA_size(rsa);

    if(key_length >= MINKEYSIZE){
        
        valid_key = true;
    } 
    RSA_free(rsa);
    return valid_key;
}
bool
check_overall_name(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert, char *website){
    bool valid_name = false;
    if(check_common_name(cert, website)){
        valid_name = true;
    } else {
        valid_name = check_subject_alt(ext_list, cert, website);
    }
    return valid_name;
}

bool
check_time(X509 *cert){

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
    bool valid_before = valid_time(before_time, current);
    bool valid_after = valid_time(current, after_time);

    return valid_before && valid_after;
       
}

bool 
valid_time(ASN1_TIME *before, ASN1_TIME *after){
    int pday, psec;
    ASN1_TIME_diff(&pday, &psec, before, after);
    if(pday > 0 || psec > 0){
        return true;
    } 
    return false;
}


bool 
check_subject_alt(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert, char *website) {
    bool valid = false;
    char *extension_data = get_extension_data(ext_list, cert, NID_subject_alt_name);
    if(extension_data!=NULL){
        
        /* Get each DNS query  */
        char *query = extension_data;
        while ((query= strtok(query, ", ")) != NULL) {
            // Extract the Subject Alternative Names from each query
            char *alt_name = malloc(strlen(query));
            strcpy(alt_name, query);
            alt_name+=strlen(DNS);
            if(check_name(alt_name, website)){
                valid  = true;
                break;
            }
            query=NULL;
        }
    }  
    return valid;
}


bool
check_common_name(X509 *cert, char* website){
    // get common name 
    X509_NAME *common_name = NULL;
    common_name = X509_get_subject_name(cert);
    char domain_cn[256] = "Domain CN NOT FOUND";
    X509_NAME_get_text_by_NID(common_name, NID_commonName, domain_cn, 256);
    return check_name(domain_cn, website);   
}
bool
check_name(char* name, char *website){
    bool valid = false;
    if(strcmp(name, website)==0){
         valid = true;
    } else {
         valid = check_wildcard(name, website);
            
    }
    return valid;
}
bool
check_wildcard(char *name, char *website){
    
    if(valid_wildcard(name)){

        // chop off the first two characters to get the website without *.
        char *domain_copy = malloc(strlen(name));
        strcpy(domain_copy, name);
        domain_copy+=WILDCARD_START;


        char *website_copy = malloc(strlen(website));
        strcpy(website_copy, website);
        
        
        char *website_full_stop;
        char *type_delimitter = ".";
        strtok_r(website_copy, type_delimitter, &website_full_stop);
        

        if(strcmp(domain_copy, website_full_stop)==0){
            return true;
        }              
    }
    return false;
}


bool 
valid_wildcard(char *domain_cn){
    char *checker = (char*) malloc(sizeof(char) * WILDCARD_START+1);
    strncpy(checker, domain_cn, WILDCARD_START);
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
        
        extension_data = ext_data(basic);
    
    }
    return extension_data;

}

char *
ext_data(X509_EXTENSION *extension) {

    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, extension, 0, 0)) {
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