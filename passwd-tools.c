// compile with gcc -lcrypt -lcrypto -o passwd-tools passwd-tools.c
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//base64
//#include "base64.h"

#define __USE_GNU
#include <crypt.h>



//md5v2 & sha1 & PBKDF2 -lcrypto
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#define PBKDF2_SALTLEN		(16)
#define PBKDF2_PRF_DEF		6
#define PBKDF2_ITER_DEF		64000
#define PBKDF2_F_SCAN		":%m[^:]:%u:%m[^:]"
#define PBKDF2_F_PRINT	        ":%s:%lu:%s:%s"

#define EVP_MAX_MDSTR_SIZE 10

const char seedMAP[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";


/* A BASE-64 EN-DE-CODER USING OPENSSL (partially by Len Schulwitz)
 */
/*This function will Base-64 encode your data.*/
unsigned long  base64encode (void *data, int len_data,char *output,unsigned long size)
{
  BIO *b64_bio, *mem_bio; //Declare two BIOs. One base64 encodes, the other stores memory.
  BUF_MEM *mem_bio_mem_ptr; //Pointer to the "memory BIO" structure holding the base64 data.
  unsigned long min_size=0;
  b64_bio = BIO_new(BIO_f_base64()); //Initialize our base64 filter BIO.
  mem_bio = BIO_new(BIO_s_mem()); //Initialize our memory sink BIO.
  BIO_push(b64_bio, mem_bio); //Link the BIOs (i.e. create a filter-sink BIO chain.)
  BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); //Don't add a newline every 64 characters.
  BIO_write(b64_bio, data, len_data); //Encode and write our b64 data.
  BIO_flush(b64_bio); //Flush data. Necessary for b64 encoding, because of pad characters.
  BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr); //Store address of mem_bio's memory structure.
  min_size=(size-1 < mem_bio_mem_ptr->length ? size-1:mem_bio_mem_ptr->length);
  memcpy(output,mem_bio_mem_ptr->data,min_size); //Copy memory
  output[min_size]=0;
  BIO_free_all(b64_bio); //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
  return min_size;
}
// output allocated space must be >= length
unsigned int base64decode(void *input, int length,unsigned char *output)
{
  BIO *b64_bio, *mem_bio;
  unsigned int len = 0;
  b64_bio = BIO_new(BIO_f_base64());
  mem_bio = BIO_new_mem_buf(input, length);
  mem_bio = BIO_push(b64_bio, mem_bio);
  // BIO_push(b64_bio, mem_bio);
  BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); //Don't add a newline every 64 characters.
  len = BIO_read(mem_bio, output, length);
  // printf("b64_dec_len = %d\n", len);
  output[len] = '\0';
  BIO_free_all(mem_bio);
  return len;
}

void genSalt(unsigned char * salt,unsigned int saltlen,const char *maps,unsigned long lMaps){
  unsigned int seed=0;
  unsigned long n=0;
  seed=time(NULL);
  for(n=0;n<saltlen;n++)
    salt[n]=maps[rand_r(&seed)%lMaps];
  
}
void genSaltBin(unsigned char * salt,unsigned int saltlen){
  unsigned int seed=0;
  unsigned long n=0;
  seed=time(NULL);
  for(n=0;n<saltlen;n++)
    salt[n]=rand_r(&seed);
  
}


char *fDigest(char *str,char *salt,unsigned long lSalt,unsigned char *digest){

  char *ret=NULL;

  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  char		md_b64[(EVP_MAX_MD_SIZE * 2) + 5];
  char		*salt_b64=NULL,*salt_bin=NULL;

  int md_len,i;
  unsigned long lRet=lSalt+EVP_MAX_MDSTR_SIZE+9+(EVP_MAX_MD_SIZE * 2);

 
  md = EVP_get_digestbyname(digest);

  if(!md) {
    printf("Unknown message digest %s\nUsing sha256\n", digest);
    md = EVP_get_digestbyname("sha256");
    digest="sha256";
  }
  
  ret=(char *)calloc(lRet,sizeof(char));
  
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  
  if(salt){
    if(salt[0]==0){
      genSaltBin(salt,lSalt);
      salt_b64=(char *)calloc(lSalt*2+5,sizeof(char));
      //      base64_encode((const char *) salt, lSalt,salt_b64, lSalt*2+5);
      base64encode(salt, lSalt,salt_b64, lSalt*2+5);
    }
    else if(salt[lSalt-1]=='='){
      salt_bin=(char *)calloc(lSalt+1,sizeof(char));
      //      lSalt=base64_decode((const char *) salt, salt_bin, lSalt+1);
      lSalt=base64decode( salt, lSalt,salt_bin);
    }
    EVP_DigestUpdate(mdctx, salt_bin?salt_bin:salt, lSalt);
  }
  
  EVP_DigestUpdate(mdctx, str, strlen(str));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);
  
  

  memset(md_b64, 0x00, sizeof md_b64);
  //base64_encode((const char *) md_value, EVP_MD_size(md),md_b64, sizeof md_b64);
  base64encode( md_value, EVP_MD_size(md),md_b64, sizeof md_b64);

  snprintf(ret,lRet,":%s:%s:%s",digest,(salt?(salt_b64?salt_b64:salt):""),md_b64);
  if(salt_b64)
    free(salt_b64);
  if(salt_bin)
    free(salt_bin);
  
  return ret;
}


/* This is an implementation of PKCS#5 v2.0 password based encryption key
 * derivation function PBKDF2.
 * SHA1 version verified against test vectors posted by Peter Gutmann
 * <pgut001@cs.auckland.ac.nz> to the PKCS-TNG <pkcs-tng@rsa.com> mailing list.
 */
/* From Atheme */
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
			   const unsigned char *salt, int saltlen, int iter,
			   const EVP_MD *digest,
			   int keylen, unsigned char *out)
{
	unsigned char digtmp[EVP_MAX_MD_SIZE], *p=NULL, itmp[4];
	int cplen=0, j=0, k=0, tkeylen=0, mdlen=0;
	unsigned long i = 1,tt;
	HMAC_CTX hctx;

	mdlen = EVP_MD_size(digest);

	HMAC_CTX_init(&hctx);
	p = out;
	tkeylen = keylen;
	if(!pass)
		passlen = 0;
	else if(passlen == -1)
		passlen = strlen(pass);
	while(tkeylen)
	{
		if(tkeylen > mdlen)
			cplen = mdlen;
		else
			cplen = tkeylen;
		/* We are unlikely to ever use more than 256 blocks (5120 bits!)
		 * but just in case...
		 */
		itmp[0] = (unsigned char)((i >> 24) & 0xff);
		itmp[1] = (unsigned char)((i >> 16) & 0xff);
		itmp[2] = (unsigned char)((i >> 8) & 0xff);
		itmp[3] = (unsigned char)(i & 0xff);
				
		HMAC_Init_ex(&hctx, pass, passlen, digest, NULL);
		HMAC_Update(&hctx, salt, saltlen);
		HMAC_Update(&hctx, itmp, 4);
		HMAC_Final(&hctx, digtmp, NULL);
		memcpy(p, digtmp, cplen);
		for(j = 1; j < iter; j++)
		{
			HMAC(digest, pass, passlen,
				 digtmp, mdlen, digtmp, NULL);
			for(k = 0; k < cplen; k++)
				p[k] ^= digtmp[k];
		}
		tkeylen-= cplen;
		i++;
		p+= cplen;
	}
	HMAC_CTX_cleanup(&hctx);
	return 1;
}

/*******************************************************************************************/

char *fPBKDF2(char *str,char *salt,unsigned long lSalt,char *sPRF){

  char *ssalt=NULL,*digestname=NULL,*ssPRF=NULL;
  char		*salt_b64=NULL,*salt_bin=NULL;
  unsigned long iter=24576,prf=0,lRes=0;
  char *result=NULL;

  const EVP_MD*	md = NULL;
  
  unsigned char	digest[EVP_MAX_MD_SIZE];
  char		digest_b64[(EVP_MAX_MD_SIZE * 2) + 5];

  if(salt && (sscanf(salt, PBKDF2_F_SCAN, &ssPRF, &iter, &ssalt) == 3)){
    salt=ssalt;
    sPRF=ssPRF;
    lSalt=strlen(ssalt);
    if(salt[lSalt-1]=='='){
      salt_bin=(char *)calloc(lSalt+1,sizeof(char));
      //      lSalt=base64_decode((const char *) salt, salt_bin, lSalt+1);
      lSalt=base64decode( salt, lSalt,salt_bin);
    }
  }
  else{
    if(salt){
      if(salt[0]==0){
	genSaltBin(salt,lSalt);
	salt_b64=(char *)calloc(lSalt*2+5,sizeof(char));
	//	base64_encode((const char *) salt, lSalt,salt_b64, lSalt*2+5);
	base64encode( salt, lSalt,salt_b64, lSalt*2+5);
      }
      else if(salt[lSalt-1]=='='){
	salt_bin=(char *)calloc(lSalt+1,sizeof(char));
	//	lSalt=base64_decode((const char *) salt, salt_bin, lSalt+1);
	lSalt=base64decode( salt, lSalt,salt_bin);
      }
    }
    else{
      if(lSalt == 0)
	lSalt=PBKDF2_SALTLEN;
    
      ssalt=(char *)calloc(lSalt+1,sizeof(char));
      salt=ssalt;
      genSaltBin(salt,lSalt);
      salt_b64=(char *)calloc(lSalt*2+5,sizeof(char));
      //      base64_encode((const char *) salt, lSalt,salt_b64, lSalt*2+5);
      base64encode( salt, lSalt,salt_b64, lSalt*2+5);
    }
  }

  if(iter == 0)
    iter=PBKDF2_ITER_DEF;

  if(sPRF){
    if(strncmp("pbkdf2-",sPRF,7) != 0){
      if(ssPRF)
	free(ssPRF);
      if(ssalt)
	free(ssalt);
      if(salt_b64)
	free(salt_b64);
      if(salt_bin)
	free(salt_bin);
      return NULL;
    }
    digestname=sPRF+7;
  }
  
  md = EVP_get_digestbyname(digestname);
  
  if(!md) {
    printf("Unknown message digest %s\nUsing sha256\n", digest);
    md = EVP_get_digestbyname("sha256");
    digestname="sha256";
  }

  
  /* Compute the PBKDF2 digest */
  size_t sl = strlen(str);
  (void) PKCS5_PBKDF2_HMAC(str, sl, (unsigned char *) salt_bin?salt_bin:salt, lSalt,
	                         iter, md, EVP_MD_size(md), digest);

  /* Convert the digest to Base 64 */
  memset(digest_b64, 0x00, sizeof digest_b64);
  //(void) base64_encode((const char *) digest, EVP_MD_size(md), digest_b64, sizeof digest_b64);
  base64encode( digest, EVP_MD_size(md), digest_b64, sizeof digest_b64);

  /* Format the result */
  lRes=(EVP_MAX_MD_SIZE * 2) + strlen(sPRF)+lSalt+30;
  result=(char *)calloc(lRes,sizeof(char));
  
    
  snprintf(result, lRes, PBKDF2_F_PRINT, sPRF, iter, (salt_b64?salt_b64:salt), digest_b64);

  if(ssPRF)
    free(ssPRF);
  if(ssalt)
    free(ssalt);
  if(salt_b64)
    free(salt_b64);
  if(salt_bin)
    free(salt_bin);
  
  return result;
  
}



char *fposix(char *str,char *salt){
  
  char *ret=NULL,*result=NULL;

  struct crypt_data data;
  char salt2[3];
  unsigned long len=0;
  unsigned int seed=0;

  seed=time(NULL);
  memset(&data,0,sizeof(struct crypt_data));
  
  if(!salt){
    //use default crypt/salt
    salt=salt2;
    salt2[2]=0;
    salt[0]=seedMAP[rand_r(&seed)%64];
    salt[1]=seedMAP[rand_r(&seed)%64];
  }
    
  result=crypt_r(str, salt,&data);
  if(!result){
    //TODO error
    return NULL;
  }
  
  len=strlen(result)+1;
  ret=(char *)calloc(len,sizeof(char));
  strncpy(ret,result,len);
  
  return ret;
}



int main(int argc,char **argv){

  OpenSSL_add_all_digests();

  char *salt=NULL;
  char nsalt[17]={0};
  char lSalt=0;
  char *res=NULL;
  char *digestname;
  
  if(argc< 3)
    return 1;


  if(strcmp(argv[1],"posix") == 0){
    if(argc==3)
      res=fposix(argv[2],NULL);
    else
      res=fposix(argv[2],argv[3]);
  }
  else if(strncmp(argv[1],"pbkdf2-",7) == 0){
    if(argc > 3){
      salt=argv[3];
      lSalt=strlen(salt);
      if(salt[0]==' ')
	salt[0]=0;
    }
    res=fPBKDF2(argv[2],salt,lSalt,argv[1]);
  }
  else{
    if(argc > 3){
      salt=argv[3];
      lSalt=strlen(salt);
      if(salt[0]==' ')
	salt[0]=0;
    }
    res=fDigest(argv[2],salt,lSalt,argv[1]);
  }
  EVP_cleanup();
  if(res){
    printf("%s",res);
    free(res);
    return 0;
  }
  return 1;
}

