#include "helib/FHE.h"
#include <iostream>
#include<stdlib.h>
#include<time.h>
#define random(x) (rand()%x)

using namespace helib;
using namespace NTL;
using namespace std;

int main(int argc, char **argv)
{
  chrono::high_resolution_clock::time_point time_start, time_end;
  chrono::microseconds time_diff;
  time_start = chrono::high_resolution_clock::now();
//初始化
	long R=1;
	long p=4999;//p决定了进行同态加密的数值可以有多大
  long r=1;
  long d=1;
  long c=2;
	long k=80;
  long w=64;
  long L=6;
//long m=32109;
	long m=FindM(k, L, c, p, d, 0, 0);

  Context context(m, p, r);
  buildModChain(context, L, c);

  context.zMStar.printout();
  cout << endl;
 
  ZZX G;
  if (d == 0)
    	G = context.alMod.getFactorsOverZZ()[0];
  else
    	G = makeIrredPoly(p, d);//进行HElib的初始化
 
 //生成同态加密的公私钥，进行同态加密运算的密文对象必须是经过同一公钥加密的数据，否则会报错
  SecKey secretKey(context);
  const PubKey& publicKey = secretKey;
  secretKey.GenSecKey(w); // A Hamming-weight-w secret key
  addSome1DMatrices(secretKey); // compute key-switching matrices that we need
 
  EncryptedArray ea(context, G);
  long nslots = ea.size();
 	
	srand((int)time(0));		
	PlaintextArray plain_text1(ea);
	vector<long> data1;
	data1.resize(nslots); 
//生成初始向量数据a b
	data1[0]=55;
	data1[1]=77; 
//将向量编码成明文对象
	encode(ea,plain_text1,data1);
	cout<<"a="<<data1[0]<<endl;
	cout<<"b="<<data1[1]<<endl; 
//加密  
	Ctxt cipher_text1(publicKey);
	ea.encrypt(cipher_text1, publicKey, plain_text1);

//生成初始向量数据x
	PlaintextArray plain_text2(ea);
	data1[0]=random(100);
	data1[1]=data1[0];
 //将向量编码成明文对象
	encode(ea,plain_text2,data1);
	cout<<"x="<<data1[0]<<endl;
  //加密 
	Ctxt cipher_text2(publicKey);
	ea.encrypt(cipher_text2,publicKey,plain_text2);
  
//生成初始向量数据y 
	PlaintextArray plain_text3(ea);
	data1[0]=random(100);
	data1[1]=data1[0];
  //将向量编码成明文对象
	encode(ea,plain_text3,data1);
	cout<<"y="<<data1[0]<<endl;
  //加密 
	Ctxt cipher_text3(publicKey);
	ea.encrypt(cipher_text3,publicKey,plain_text3);
 
 //运算
	cout<<"a*x+y b*x+y"<<endl;
	cipher_text1*=cipher_text2;
	cipher_text1+=cipher_text3;
	cout<<"结束"<<endl;
 
 //解密
	PlaintextArray de(ea);
	cout<<"解密："<<endl;
	ea.decrypt(cipher_text1, secretKey, de);
	vector<long> array2;
	array2.resize(ea.size());
  //把解密的结果还原成向量
	decode(ea,array2,de);
	cout<<"decrypt:"<<array2<<endl;

  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "Done [" << time_diff.count() << " microseconds]" << endl;

  return 0;
}
