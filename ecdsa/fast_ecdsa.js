var ECDSA = {
	// returns random big int in the range [1,modulus-1]
	getRandomBigInt: function (limit){
		if(window.crypto || window.msCrypto){
			var length = limit.bitLength(); 
			if(length != 512 && length != 256) {alert("wrong modulus length");return;}
			var rand_arr = new Uint8Array(length/8);
			if(window.crypto){window.crypto.getRandomValues(rand_arr);}else{window.msCrypto.getRandomValues(rand_arr);}
			var tmpstring;var resultstring = "";
			for (var i = 0; i < rand_arr.length; i++) {
				tmpstring="";
				if (rand_arr[i].toString(2).length<8){
					for(var j = 0;j<8-rand_arr[i].toString(2).length;j++){
						tmpstring+=0;
					}
					tmpstring+=rand_arr[i].toString(2);
				}
				else{
					tmpstring=rand_arr[i].toString(2);
				}
				resultstring += tmpstring;
			}
			var res = new BigInteger(resultstring, 2);
			return res.mod(limit.subtract(BigInteger.ONE)).add(BigInteger.ONE);
		}else{
			var rng = new SecureRandom();
			return new BigInteger(limit.bitLength(), rng).mod(limit.subtract(BigInteger.ONE)).add(BigInteger.ONE);
		}
	},
	sign: function (hash, priv) {
		var ecparams = getSECCurveByName(usedCurve); var w=4;
		var d = priv;
		var n = ecparams.getN();
		var e = BigInteger.fromByteArrayUnsigned(hash);
		do {
			var k = ECDSA.getRandomBigInt(n);
			var G = ecparams.getG();
			var curve=ecparams.getCurve();
			var Q=new ECPointFp(curve);
			Q = ecpComb2Mult(k,Q,w,GLOBAL_precomp,n.bitLength());
			var r = Q.getX().toBigInteger().mod(n);
		} while (r.compareTo(BigInteger.ZERO) <= 0);
		var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
		return [Q,s];
	},
	verify: function (hash, sig, pubkey) {
		var ecparams = getSECCurveByName(usedCurve); var w=4;
		var R=sig[0];
		var s=sig[1];
		var Q=pubkey;
		var e = BigInteger.fromByteArrayUnsigned(hash);
		var n = ecparams.getN();
		var G = ecparams.getG();
		var r = R.getX().toBigInteger();
		if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0)
			return false;

		if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0)
			return false;
		var c = s.modInverse(n);
		var u1 = e.multiply(c);
		var u2 = r.multiply(c).mod(n);
		var uv=u2.extEuclidean(n); var u=uv[0], v=uv[1];
		var v_signum=0;
		if(v.signum()<0){
			v=v.negate(); v_signum=-1;
		}
		else{
			R=R.negate();
		}
		var p2=Q.multiplyTwo(u,R,v);
		var ves=v.multiply(u1).mod(n);
		var curve=ecparams.getCurve();
		var p1=new ECPointFp(curve);
		p1 = ecpComb2Mult(ves,p1,w,GLOBAL_precomp,n.bitLength()); if(v_signum==-1) p1=p1.negate();
		var point=p1.add(p2);
		return point.isInfinity();
	}
};
