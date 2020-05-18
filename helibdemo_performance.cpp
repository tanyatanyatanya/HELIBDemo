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

	long R=1;
	long p=4999;//p决定了进行同态加密的数值可以有多大
	long r=1;
	long d=1;
	long c=2;
	long k=80;
	long w=64;
  long L=4;
	long s=0;
//long m=32109; 
	long m=FindM(k, L, c, p, d, s, 0);

	Context context(m, p, r);
  buildModChain(context, L, c);

  context.zMStar.printout();
  cout << endl;
 
  ZZX G;
  if (d == 0)
    	G = context.alMod.getFactorsOverZZ()[0];
  else
    	G = makeIrredPoly(p, d);//进行HElib的初始化
 
	time_start = chrono::high_resolution_clock::now();
  SecKey secretKey(context);
  const PubKey& publicKey = secretKey;
  secretKey.GenSecKey(w); // A Hamming-weight-w secret key
  addSome1DMatrices(secretKey); // compute key-switching matrices that we need
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "Key generation time:" << time_diff.count() << " microseconds" << endl;
 
  EncryptedArray ea(context, G);
  long nslots = ea.size();
 	
	srand((int)time(0));
		
	PlaintextArray plain_text1(ea);
	vector<long> data1;
	data1.resize(nslots);

	data1[0]=random(100);//向量数据
	cout << "-----data1="<<data1[0]<<"-----"<< endl;

	time_start = chrono::high_resolution_clock::now();
	encode(ea,plain_text1,data1);//将向量编码成明文对象
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "encoding time:" << time_diff.count() << " microseconds" << endl;	

	Ctxt cipher_text1(publicKey);

	time_start = chrono::high_resolution_clock::now();
	ea.encrypt(cipher_text1, publicKey, plain_text1);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "encryption time:" << time_diff.count() << " microseconds" << endl;
 	
	Ctxt cipher_result1(publicKey);
	cipher_result1=cipher_text1;

	time_start = chrono::high_resolution_clock::now();
	cipher_result1+=cipher_text1;
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "addition time:" << time_diff.count() << " microseconds" << endl;

	time_start = chrono::high_resolution_clock::now(); 
	cipher_result1-=cipher_text1;
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "subtraction time:" << time_diff.count() << " microseconds" << endl;
    
	time_start = chrono::high_resolution_clock::now(); 
	cipher_text1*=cipher_text1;
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "multplication time:" << time_diff.count() << " microseconds" << endl;

	PlaintextArray de(ea);

	time_start = chrono::high_resolution_clock::now();
	ea.decrypt(cipher_result1, secretKey, de);
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "decryption time:" << time_diff.count() << " microseconds" << endl;
  

	vector<long> result;
	result.resize(ea.size());

	time_start = chrono::high_resolution_clock::now();
	decode(ea,result,de);//把解密的结果还原成向量
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "decoding time:" << time_diff.count() << " microseconds" << endl;
 
	cout << "-----result="<<result[0]<<"-----"<< endl; 

  return 0;
}
