// This is an extraction and slightly modification of the 
// eccunique.js file by Laurie Haustenne, Quentin De Neyer, 
// Olivier Pereira

// It contains the functions precomputeComb2, ecpComb2Mult 
// and factResize used for fixed base point multiplication
// using precomputed data that depends on the fixed base point.

// Original eccunique.js file:
// Copyright (C) 2011-2012 Laurie Haustenne, Quentin De Neyer, 
// Olivier Pereira (Universite catholique de Louvain).
// See "LICENSE-precomp" for details on original file.

function precomputeComb2(P,w,curve,bit){
	var d=Math.ceil(bit/w);	
	var e=Math.ceil(d/2);
	var r=1<<w;
	var tab=new Array();
	tab[0]=P;	tab[w]=P.multiplyPowTwo(e);
	for(var i=1;i<w;i++){
		tab[i]=tab[i-1].multiplyPowTwo(d);tab[i+w]=tab[i].multiplyPowTwo(e);}
	var precomp=new Array();
	var j=0;
	precomp[0]=new ECPointFp(curve);
	precomp[r]=new ECPointFp(curve);
	for(var ipc=1;ipc<r;ipc++){
		var fact=1;
		var jpc=ipc;
		while((jpc&1)==0){fact+=1;jpc=jpc>>1;}
		precomp[ipc]=precomp[ipc-(1<<(fact-1))].add(tab[fact-1]);
		precomp[ipc+r]=precomp[ipc+r-(1<<(fact-1))].add(tab[w+fact-1]);
	}
	return precomp;
}

function ecpComb2Mult(k,Q,w,precomp,bit){
	// input : Window width w,  k
	//  d = ceil(t/w), e = ceil(d/2)
	// output : kP
	var d=Math.ceil(bit/w);
	var e=Math.ceil(d/2);	
	var kTab=factResize(k,w,bit); 
	Q=precomp[kTab[e-1]].add(precomp[kTab[2*e-1]+(1<<w)]);
	for(var i=e-2;i>=0;i--){
		Q=Q.twice().add(precomp[kTab[i]]).add(precomp[kTab[i+e]+(1<<w)]);
	}
	return Q;
}
				
function factResize(k,w,bit){
	//input : key, window size
	//output : k such that k[i]=K_i^(w-1) ... K_i^(0)
	var d=Math.ceil(bit/w);
	var factArr=new Array();
	for(var i=0;i<2*Math.ceil(d/2);i++){factArr[i]=0;}
	for (ind=d-1;ind>=0;ind--){
		for (var j=0;j<w;j++){
			if(k.testBit(d*j+ind)){factArr[ind]=factArr[ind]+(1<<(j));}
		}
	}
	return factArr;
}
