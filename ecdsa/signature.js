function ECSignature(param){
	this.ecparams = getSECCurveByName(param[7]);
	this.curve = this.ecparams.curve;
	this.Q = new ECPointFp(this.curve,
			this.curve.fromBigInteger(new BigInteger(param[1], 16)),
			this.curve.fromBigInteger(new BigInteger(param[2], 16)));
	this.m = Crypto.util.hexToBytes(param[3]);
	this.R = new ECPointFp(this.curve,
			this.curve.fromBigInteger(new BigInteger(param[4], 16)),
			this.curve.fromBigInteger(new BigInteger(param[5], 16)));
	this.s = new BigInteger(param[6], 16);
	
	this.verify = function(){
		var sig = [this.R,this.s];
		return ECDSA.verify(this.m, sig, this.Q);
	}
}

function batchSingleSigner(signature){
	var n = signature[0].ecparams.getN();
    var G = signature[0].ecparams.getG();
    var RHS = signature[0].curve.getInfinity();
    
    var a = BigInteger.ZERO; var b = BigInteger.ZERO;
    var s_inv = new Array(); var m = new Array(); var r = new Array();
    
    for(var i=0;i<signature.length;i++){
    	r[i]=signature[i].R.getX().toBigInteger();
    	if (r[i].compareTo(BigInteger.ONE) < 0 ||
                r[i].compareTo(n) >= 0)
              return false;
	    if (signature[i].s.compareTo(BigInteger.ONE) < 0 ||
	    		signature[i].s.compareTo(n) >= 0)
	          return false;
	    m[i] = BigInteger.fromByteArrayUnsigned(signature[i].m);
	    s_inv[i] = signature[i].s.modInverse(n);
	    a=a.add(m[i].multiply(s_inv[i]).mod(n)); 
	    b=b.add(r[i].multiply(s_inv[i]).mod(n));
	    RHS=RHS.add(signature[i].R);
    }
    a=a.mod(n);b=b.mod(n);
    RHS=RHS.negate();
    
    if(G.multiplyTwo(a,signature[0].Q,b).add(RHS).isInfinity()){
    	return true;
    }else{
    	return false;
    }
}

function batchMultipleSigner(signature){
	var n = signature[0].ecparams.getN();
	var G = signature[0].ecparams.getG();
	var RHS = signature[0].curve.getInfinity();   
	var a = BigInteger.ZERO;var b = signature[0].curve.getInfinity();
	var s_inv = new Array();var m = new Array();var r = new Array();    
	for(var i=0;i<signature.length;i++){
		r[i]=signature[i].R.getX().toBigInteger();
		if (r[i].compareTo(BigInteger.ONE) < 0 || r[i].compareTo(n) >= 0)
			return false;
		if (signature[i].s.compareTo(BigInteger.ONE) < 0 || signature[i].s.compareTo(n) >= 0)
			return false;
		m[i] = BigInteger.fromByteArrayUnsigned(signature[i].m);
		s_inv[i] = signature[i].s.modInverse(n);
		a=a.add(m[i].multiply(s_inv[i]).mod(n)); 
		b=b.add( signature[i].Q.multiply(r[i].multiply(s_inv[i]).mod(n)) );
		RHS=RHS.add(signature[i].R);
	}
	a=a.mod(n);
	RHS=RHS.negate();
	if(G.multiply(a).add(b).add(RHS).isInfinity()){
		return true;
	}else{
		return false;
	}
}
