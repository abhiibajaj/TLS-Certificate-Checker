/* A simple TLS certificate checker
The path to the csv file is specified on commandline

The input file is read and each certificate in file is validated
with the output being written in the specified format to 'output.csv'

This was adapted from the certexample.c file provided by Assignment2Example 
on GitLab

To compile: make

 Name: Arpit Bajaj
 Login: bajaja@student.unimelb.edu.au
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
#include <assert.h>

/* Minimum Key Size in Bytes: converted from bits to bytes */
#define MINKEYSIZE 2048/8  

/* Constraints to check for in certificate*/
#define CA_CONSTRAINT "CA:FALSE" 
#define TLS "TLS Web Server Authentication"

/* Starting format of Wildcard and DNS */
#define WILDCARD "*."
#define DNS "DNS:"

/* Formatted for ease of writing to output */
#define VALID ",1\r\n"
#define INVALID ",0\r\n"

/* The file the output is written to*/
#define OUTPUT_FILE "output.csv"

/* Extension doesn't exist */
#define NO_EXT -1



/****************************************************************************************/
/* Function prototypes */

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
bool check_subject_alt(const STACK_OF(X509_EXTENSION) *ext_list, 
                        X509 *cert, char *website);
bool check_overall_name(const STACK_OF(X509_EXTENSION) *ext_list, 
                        X509 *cert, char *website);
bool check_extended_key(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert);
bool check_certificate(const STACK_OF(X509_EXTENSION) *ext_list, 
                        X509 *cert, char *website);

/****************************************************************************************/

int 
main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr,"ERROR, no path provided\n");
        exit(1);
    }
    /* Get the path to the file */
    char *filepath = argv[1];

    /* Open input in read mode and output in write mode */
    FILE *input;
    FILE *output;
    input = fopen(filepath, "r");
    assert(input!=NULL);
    output = fopen(OUTPUT_FILE, "w");
    assert(output!=NULL);

    /* Initialise required variables */
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    char *test_cert_example;
    char *result;
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Read every line in the input file*/
    while ((read = getline(&line, &len, input)) != -1) {


        result = INVALID;

        /* retain a copy of original due to strtok */
        char *original_nl = malloc(strlen(line));
        strcpy(original_nl, line);

        /* Get the website from the line */
        char *website_nl;
        char *type_delimitter = ",";
        strtok_r(line, type_delimitter, &website_nl);

        /* Get rid of new line from the website */
        char *website = strtok(website_nl, "\r\n");
        test_cert_example = malloc(strlen(line));
        strcpy(test_cert_example, line);     
    

        /* create BIO object to read certificate */
        certificate_bio = BIO_new(BIO_s_file());

        /* Read certificate into BIO */
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

        /* get certificate extensions and info */
        cert_inf = cert->cert_info;
        ext_list = cert_inf->extensions;

        
        /* check certificate */
        bool valid_certificate = check_certificate(ext_list, cert, website);
        
        /* Certificate is valid */
        if (valid_certificate){
            result = VALID;
        }
        
        /* get rid of new line from original */
        char *original =strtok(original_nl, "\r\n");

        /* combine original line with the result */
        char *output_line = malloc(strlen(original)+strlen(result)+1); // one extra for null byte
        strcpy(output_line, original);
        strcat(output_line, result);

        /* Write to output*/
        fputs(output_line, output);
       
        //*********************
        // End of Example code
        //*********************
        X509_free(cert);
        BIO_free_all(certificate_bio);
            
    }

    fclose(input);
    fclose(output);
    
    return 0;
}

/****************************************************************************************/

/* Validates the certificate via testing as specified by the spec 
    Must pass all tests to return true */
bool 
check_certificate(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert, char *website){
    bool valid_name = check_overall_name(ext_list, cert, website);
    bool valid_time = check_time(cert);
    bool valid_key = check_key(cert);       
    bool valid_basic = check_basic_constraints(ext_list, cert);               
    bool valid_extended_key = check_extended_key(ext_list, cert);

    bool valid_certificate = valid_name && valid_time && valid_key 
                             && valid_basic && valid_extended_key;

    return valid_certificate;
}

/****************************************************************************************/

/* Checks the extended key usage returning true if contains TLS */
bool
check_extended_key(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert){
    char *extension_data = get_extension_data(ext_list, cert, NID_ext_key_usage);
    return check_containing(extension_data, TLS);
}

/****************************************************************************************/

/* Checks the basic constraints returning true if contains CA_CONSTRAINT */
bool 
check_basic_constraints(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert){
    char *extension_data = get_extension_data(ext_list, cert, NID_basic_constraints);
    return check_containing(extension_data, CA_CONSTRAINT);
    
}

/****************************************************************************************/

/* Returns true if extension data is a substring of constraint */
bool
check_containing(char *extension_data, char *constraint){
    if(strstr(extension_data, constraint)){
        return true;
    } 
    return false;
}

/****************************************************************************************/

/* Returns true if key size is greater than or equal to MINKEYSIZE */

bool 
check_key(X509 *cert){

    /* Get key from certificate  */
    bool valid_key = false;
    EVP_PKEY *cert_key = X509_get_pubkey(cert);
    RSA *rsa = EVP_PKEY_get1_RSA(cert_key);

    /* Get length of key in bytes */
    int key_length = RSA_size(rsa);

    
    if(key_length >= MINKEYSIZE){
        valid_key = true;
    } 
    RSA_free(rsa);
    return valid_key;
}

/****************************************************************************************/

/* Returns if the website matches via eiter common name, wildcard or 
    Subject Alternative Name */
bool
check_overall_name(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert, char *website){
    bool valid_name = false;

    /* If common name does not match, check SAN */
    if(check_common_name(cert, website)){
        valid_name = true;
    } else {
        valid_name = check_subject_alt(ext_list, cert, website);
    }
    return valid_name;
}

/****************************************************************************************/

/* Returns true if both the from time and the expiry time is valid */
bool
check_time(X509 *cert){

    /* Get the current time */
    time_t rawtime;    
    time(&rawtime);
    localtime (&rawtime);

    /* Convert it to ASN1_TIME for comparison*/
    ASN1_TIME *current = NULL;
    ASN1_TIME_set(current, rawtime);

    /* Get the before */
    ASN1_TIME *before_time = X509_get_notBefore(cert);
        
    /* Get the after */
    ASN1_TIME *after_time = X509_get_notAfter(cert);

    /* Test both are valid */
    bool valid_before = valid_time(before_time, current);
    bool valid_after = valid_time(current, after_time);

    return valid_before && valid_after;
       
}
/****************************************************************************************/

/* Gets the difference between the times and returns true if after occurs after before */
bool 
valid_time(ASN1_TIME *before, ASN1_TIME *after){
    int pday, psec;
    ASN1_TIME_diff(&pday, &psec, before, after);
    if(pday > 0 || psec > 0){
        return true;
    } 
    return false;
}

/****************************************************************************************/

/* Returns true if the website matches one of the subject alternative names*/
bool 
check_subject_alt(const STACK_OF(X509_EXTENSION) *ext_list, X509 *cert, char *website) {

    bool valid = false;
    char *extension_data = get_extension_data(ext_list, cert, NID_subject_alt_name);

    
    if(extension_data!=NULL){
        /* Get each DNS query  */
        char *query = extension_data;
        while ((query= strtok(query, ", ")) != NULL) {
            /* Extract the Subject Alternative Names from each query */
            char *alt_name = malloc(strlen(query));
            strcpy(alt_name, query);
            alt_name+=strlen(DNS);

            /* check if the alt_name matches website, exitting loop if true */
            if(check_name(alt_name, website)){
                valid  = true;
                break;
            }
            query=NULL;
        }
    }  
    return valid;
}

/****************************************************************************************/

/* Returns true if the common name is the same as website name */
bool
check_common_name(X509 *cert, char* website){

    /* Extract the common name from the certificate */ 
    X509_NAME *common_name = NULL;
    common_name = X509_get_subject_name(cert);
    char domain_cn[256] = "Domain CN NOT FOUND";
    X509_NAME_get_text_by_NID(common_name, NID_commonName, domain_cn, 256);
    return check_name(domain_cn, website);   
}

/****************************************************************************************/

/* Returns true if name matches website exactly or via wildcard */
bool
check_name(char* name, char *website){
    bool valid = false;

    if(strcmp(name, website)==0){
        /* Matched exactly */
         valid = true;
    } else {
        /* Didn't match exactly, try wildcard*/
         valid = check_wildcard(name, website);
            
    }
    return valid;
}

/****************************************************************************************/

/* Returns true if name matches via Wilcard */
bool
check_wildcard(char *name, char *website){
    
    /* Ensure certificate name value is a wilcard*/
    if(valid_wildcard(name)){

        /* chop off the first two characters to get the website without *. */
        char *domain_copy = malloc(strlen(name));
        strcpy(domain_copy, name);
        domain_copy+=strlen(WILDCARD);

        /* Use copy due to strtok */
        char *website_copy = malloc(strlen(website));
        strcpy(website_copy, website);

        /* Remove upto the first full stop, storing the rest in website_full_stop */
        char *website_full_stop;
        char *type_delimitter = ".";
        strtok_r(website_copy, type_delimitter, &website_full_stop);
        
        /* Compare wildcard to first full stop removed website */
        if(strcmp(domain_copy, website_full_stop)==0){
            return true;
        }              
    }
    return false;
}

/****************************************************************************************/

/* Returns true if the the domain is a valid wildcard */

bool 
valid_wildcard(char *domain_cn){

    size_t wildcard_length = strlen(WILDCARD);
    char *checker = (char*) malloc(sizeof(char) * wildcard_length+1); // one extra for null

    /* Copy the first wildcard length characters to checker */
    strncpy(checker, domain_cn, wildcard_length);
    checker[wildcard_length] = '\0';

    /* Returns true if the checker equals WILDCARD*/
    if(strcmp(checker, WILDCARD)==0){
        return true;
    }
    return false;
}

/****************************************************************************************/

/* If the extenstion exists, returns the data associated with the extension 
    Returns null otherwise */
char *
get_extension_data(const STACK_OF(X509_EXTENSION) *ext_list, 
                    X509 *cert, int NID) {

    /* Exists equals -1 if extension doesn't exist*/
    int exists = X509v3_get_ext_by_NID(ext_list, NID, -1);
    char* extension_data=NULL; 

    /* Only try get the data if it exists */
    if(exists!=NO_EXT){
        /* Get the extension */
        X509_EXTENSION *basic = X509_get_ext(cert, exists);

        /* Can be used if want extension name*/
        ASN1_OBJECT *basic_obj = X509_EXTENSION_get_object(basic);
        char basic_buff[1024]; 
        OBJ_obj2txt(basic_buff, 1024, basic_obj, 0);
        
        /* Get the extenstion data */
        extension_data = ext_data(basic);
    
    }
    return extension_data;

}

/****************************************************************************************/

/* Returns the extension data based on the input extension via the BIO
    Adapted straight from provided example on GitLab */

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

/****************************************************************************************/
