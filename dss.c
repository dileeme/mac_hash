#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long modexp(long base,long exp,long mod){
    long result=1;
    base%=mod;
    while(exp>0){
        if(exp%2==1) result=(result*base)%mod;
        exp/=2;
        base=(base*base)%mod;
    }
    return result;
}

long modinv(long a,long m){
    long m0=m,t,q;
    long x0=0,x1=1;
    if(m==1) return 0;
    while(a>1){
        q=a/m;
        t=m;
        m=a%m,a=t;
        t=x0;
        x0=x1-q*x0;
        x1=t;
    }
    if(x1<0) x1+=m0;
    return x1;
}

long simple_hash(unsigned char *msg,long len,long q){
    long h=0;
    for(int i=0;i<len;i++) h=(h+msg[i])%q;
    return h;
}

unsigned char* read_file(const char *filename,long *length){
    FILE *file=fopen(filename,"rb");
    fseek(file,0,SEEK_END);
    *length=ftell(file);
    rewind(file);
    unsigned char *buffer=malloc(*length);
    fread(buffer,1,*length,file);
    fclose(file);
    return buffer;
}

int main(int argc,char *argv[]){
    if(argc!=2) return 1;

    long p=23;
    long q=11;
    long g=2;

    long x=3;
    long y=modexp(g,x,p);

    long len;
    unsigned char *message=read_file(argv[1],&len);

    long h=simple_hash(message,len,q);

    long k=5;
    long r=modexp(g,k,p)%q;
    long kinv=modinv(k,q);
    long s=(kinv*(h + x*r))%q;

    printf("Signature:\n");
    printf("r = %ld\n",r);
    printf("s = %ld\n",s);

    long w=modinv(s,q);
    long u1=(h*w)%q;
    long u2=(r*w)%q;

    long v=((modexp(g,u1,p)*modexp(y,u2,p))%p)%q;

    printf("Verification:\n");
    if(v==r) printf("Valid Signature\n");
    else printf("Invalid Signature\n");

    free(message);
    return 0;
}
