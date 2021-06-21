#include<stdio.h>
#include<string.h>
#include<stdlib.h>
typedef struct ShaMes{
    unsigned char* mes;
    int len;//单位是字节
}ShaMes;
unsigned int H[] = { 
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
unsigned int K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
//循环右移x位
unsigned int S(unsigned int num,int x){
    return (num >> x) | (num << (32 - x));
}
//右移x位
unsigned int R(unsigned int num,int x){
    return num >> x;
}

/*------------------------------------6个逻辑函数------------------------------------*/
unsigned int Ch(unsigned int x,unsigned int y,unsigned int z){
    return (x&y) ^ (~x&z);
}
unsigned int Maj(unsigned int x,unsigned int y,unsigned int z){
    return (x&y) ^ (x&z) ^ (y&z);
}
unsigned int Sigma0(unsigned int x){
    return S(x,2) ^ S(x,13) ^ S(x,22);
}
unsigned int Sigma1(unsigned int x){
    return S(x,6) ^ S(x,11) ^ S(x,25);
}
unsigned int Alpha0(unsigned int x){
    return S(x,7) ^ S(x,18) ^ R(x,3);
}
unsigned int Alpha1(unsigned int x){
    return S(x,17) ^ S(x,19) ^ R(x,10);
}
/*------------------------------------End------------------------------------*/

//消息预处理——补位
ShaMes* HandleMessage(char *message){
    
    ShaMes *s = (ShaMes *)malloc(sizeof(ShaMes));
    int mlen = strlen(message);
    int last = (mlen*8) % 512;
    if (last < 448){
        last = 448 - last;
    }else if (last >= 448){
        last = 512 - (last - 448);
    }
    message = (char*)realloc(message,mlen+last/8+8);
    int len = mlen;
    message[len] = 0x80;
    //printf("%s\n",message);
    for (int i=1;i<last/8;i++){
        message[++len] = 0x00;
    }
    for (int i=0;i<4;i++){
        message[++len] = 0x00;
    }
    for (int i=0;i<4;i++){
        message[++len] = (mlen*8)>>((3-i)*8);
    }
    s->mes = message;
    s->len = len+1;
    return s;
}

void Hash(unsigned int* m,int len){
    unsigned int a,b,c,d,e,f,g,h,T1,T2;
    unsigned int W[64];
    for (int i=0;i<len/16;i++){
        for (int k=0;k<16;k++){
            W[k] = m[i*16+k];
        }
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];
        for (int j=0;j<64;j++){
            if (j>=16){
                W[j] = Alpha1(W[j-2]) + W[j-7]+ Alpha0(W[j-15]) + W[j-16];
            }
            T1 = h + Sigma1(e) + Ch(e,f,g) + K[j] + W[j];
            T2 = Sigma0(a) + Maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];
        H[5] = f + H[5];
        H[6] = g + H[6];
        H[7] = h + H[7];
    }
}

unsigned int* SplitMessage(ShaMes *s){
    unsigned int* m = (unsigned int*)malloc(s->len/4*sizeof(unsigned int));
    memset(m,0,s->len/4*sizeof(unsigned int));
    for (int i=0;i<s->len/4;i++){
        for (int j=0;j<4;j++){ 
            m[i] += (unsigned char)s->mes[i*4+j];
            if (j<3){
                m[i] = m[i] << 8;
            }
        }
        //printf("i=%x,mes=%08X\n",i,m[i]);
    }
    return m;
}

void SHA256(char *message){
    ShaMes *shaMes = HandleMessage(message);//得到补位后的message
    unsigned int *m = SplitMessage(shaMes);//拆分message
    Hash(m,shaMes->len/4);
}
int main(){
    char *str = "BlockChain";
    char *message = (char*)malloc(strlen(str));
    strcpy(message,str);
    printf("raw message is %s\n",message);
    SHA256(message);
    for (int i=0;i<8;i++){
        printf("%08x",H[i]);
    }
    printf("\n");
    return 0;
}