#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LEFTROTATE(x,c) (((x)<<(c))|((x)>>(32-(c))))

uint32_t r[]={
7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};

uint32_t k[]={
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};

void md5(uint8_t *msg,size_t len,uint8_t *digest){
    uint32_t h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476;
    size_t new_len=len+1;
    while(new_len%64!=56)new_len++;
    uint8_t *buffer=calloc(new_len+8,1);
    memcpy(buffer,msg,len);
    buffer[len]=0x80;
    uint64_t bits=len*8;
    memcpy(buffer+new_len,&bits,8);
    for(size_t offset=0;offset<new_len;offset+=64){
        uint32_t *w=(uint32_t*)(buffer+offset);
        uint32_t a=h0,b=h1,c=h2,d=h3,f,g;
        for(uint32_t i=0;i<64;i++){
            if(i<16){f=(b&c)|((~b)&d);g=i;}
            else if(i<32){f=(d&b)|((~d)&c);g=(5*i+1)%16;}
            else if(i<48){f=b^c^d;g=(3*i+5)%16;}
            else{f=c^(b|(~d));g=(7*i)%16;}
            uint32_t temp=d;
            d=c;
            c=b;
            b=b+LEFTROTATE(a+f+k[i]+w[g],r[i]);
            a=temp;
        }
        h0+=a;h1+=b;h2+=c;h3+=d;
    }
    memcpy(digest,&h0,4);
    memcpy(digest+4,&h1,4);
    memcpy(digest+8,&h2,4);
    memcpy(digest+12,&h3,4);
    free(buffer);
}

void print_hex(uint8_t *data,int len){
    for(int i=0;i<len;i++)printf("%02x",data[i]);
    printf("\n");
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
    if(argc!=2)return 1;
    long len;
    unsigned char *msg=read_file(argv[1],&len);
    uint8_t first[16];
    uint8_t second[16];
    md5(msg,len,first);
    md5(first,16,second);
    print_hex(second,16);
    free(msg);
    return 0;
}
