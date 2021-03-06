// This is a modification of the ec.js file by Tom Wu

// The coordinates were changed to projective Jacobian
// format. Point addition and doubling functions are 
// modified accordingly. The simultaneous point 
// multiplication was replaced by a faster windowed 
// approach. Eventually a function for multiplying a 
// point by a power of two was added

// Original ec.js file:
// Copyright (c) 2005  Tom Wu
// See "LICENSE-jsbn" for details on original file.

// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2_mod.js

// ----------------
// ECFieldElementFp

// constructor
function ECFieldElementFp(q,x) {
    this.x = x;
    // TODO if(x.compareTo(q) >= 0) error
    this.q = q;
}

function feFpEquals(other) {
    if(other == this) return true;
    return (this.q.equals(other.q) && this.x.equals(other.x));
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;

// ----------------
// ECPointFp

// constructor
function ECPointFp(curve,x,y,z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    // Projective coordinates: either zinv == null or z * zinv == 1
    // z and zinv are just BigIntegers, not fieldElements
    if(z == null) {
      this.z = BigInteger.ONE;
    }
    else {
      this.z = z;
    }
    this.zinv = null;
    //TODO: compression flag
}

function pointFpGetX() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    var zinv2 = this.zinv.square();
    var r = this.x.toBigInteger().multiply(zinv2).mod(this.curve.q);
    //this.curve.reduce(r);
    return this.curve.fromBigInteger(r);
}

function pointFpGetY() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    var zinv2 = this.zinv.square();
    var zinv3 = zinv2.multiply(this.zinv);
    var r = this.y.toBigInteger().multiply(zinv3).mod(this.curve.q);
    //this.curve.reduce(r);
    return this.curve.fromBigInteger(r);
}

function pointFpEquals(other) {
    if(other == this) return true;
    if(this.isInfinity()) return other.isInfinity();
    if(other.isInfinity()) return this.isInfinity();
	var z1sq = this.z.square(); var z1p3 = z1sq.multiply(this.z);
	var z2sq = other.z.square(); var z2p3 = z2sq.multiply(other.z);
    var u, v;
    // u = Y2 * Z1^3 - Y1 * Z2^3
    u = other.y.toBigInteger().multiply(z1p3).subtract(this.y.toBigInteger().multiply(z2p3)).mod(this.curve.q);
    if(!u.equals(BigInteger.ZERO)) return false;
    // v = X2 * Z1^2 - X1 * Z2^2
    v = other.x.toBigInteger().multiply(z1sq).subtract(this.x.toBigInteger().multiply(z2sq)).mod(this.curve.q);
    return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
    if((this.x == null) && (this.y == null)) return true;
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
    if(this.isInfinity()) return b;
    if(b.isInfinity()) return this;
    
    var T1 = this.x.toBigInteger(); //this step computes U0 (if z1=1)
    var T2 = this.y.toBigInteger(); //this step computes S0 (if z1=1)
    var T3 = this.z
    var T4 = b.x.toBigInteger();
    var T5 = b.y.toBigInteger();
    if(!BigInteger.ONE.equals(b.z)){
    	var T6 = b.z;
    	var T7 = T6.square().mod(this.curve.q);
    	T1 = T1.multiply(T7).mod(this.curve.q); //this step computes U0 (if z1!=1)
    	T7 = T6.multiply(T7).mod(this.curve.q);
    	T2 = T2.multiply(T7).mod(this.curve.q); //this step computes S0 (if z1!=1)
    }
    var T7 = T3.square().mod(this.curve.q);
    T4 = T4.multiply(T7).mod(this.curve.q); //this step computes U1
    T7 = T3.multiply(T7).mod(this.curve.q);
    T5 = T5.multiply(T7).mod(this.curve.q); //this step computes S1
    T4 = T1.subtract(T4); //this step computes W
    T5 = T2.subtract(T5); //this step computes R
    if(BigInteger.ZERO.equals(T4)) {
        if(BigInteger.ZERO.equals(T5)) {
            return this.twice(); // this == b, so double
        }
	return this.curve.getInfinity(); // this = -b, so infinity
    }
    T1 = T1.shiftLeft(1).subtract(T4); //this step computes T
    T2 = T2.shiftLeft(1).subtract(T5); //this step computes M
    if(!BigInteger.ONE.equals(b.z)){
    	T3 = T3.multiply(T6).mod(this.curve.q);
    }
    T3 = T3.multiply(T4).mod(this.curve.q); //this step computes z2
    T7 = T4.square().mod(this.curve.q);
    T4 = T4.multiply(T7);
    T7 = T1.multiply(T7);
    T1 = T5.square().mod(this.curve.q);
    T1 = T1.subtract(T7).mod(this.curve.q); //this step computes x2
    T7 = T7.subtract(T1.shiftLeft(1)); //this step computes V
    T5 = T5.multiply(T7);
    T4 = T2.multiply(T4);
    T2 = T5.subtract(T4);
    T2 = T2.shiftRight(1).mod(this.curve.q); //this step computes y2

    return new ECPointFp(this.curve, this.curve.fromBigInteger(T1), this.curve.fromBigInteger(T2), T3);
}

function pointFpTwice() {
	if(this.isInfinity()) return this;
	if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();
	var a = this.curve.a.toBigInteger();
	var THREE = new BigInteger("3");
	var T1 = this.x.toBigInteger();
    var T2 = this.y.toBigInteger(); 
    var T3 = this.z     
	if(a.compareTo(this.curve.q.subtract(THREE))==0){
		var T4 = T3.square().mod(this.curve.q);
		var T5 = T1.subtract(T4).mod(this.curve.q);
		T4 = T1.add(T4).mod(this.curve.q);
		T5 = T4.multiply(T5).mod(this.curve.q);
		T4 = T5.shiftLeft(1).mod(this.curve.q);
		T4 = T4.add(T5).mod(this.curve.q); //compute M
	} 
	else{
		var T4 = a;
		var T5 = T3.square().mod(this.curve.q);
		T5 = T5.square().mod(this.curve.q);
		T5 = T4.multiply(T5).mod(this.curve.q);
		T4 = T1.square().mod(this.curve.q);
		T4 = T4.multiply(THREE).mod(this.curve.q);
		T4 = T4.add(T5).mod(this.curve.q); //compute M
	}
	T3 = T2.multiply(T3).mod(this.curve.q);
	T3 = T3.shiftLeft(1).mod(this.curve.q); //compute z2
	T2 = T2.square().mod(this.curve.q);
	T5 = T1.multiply(T2).mod(this.curve.q);
	T5 = T5.shiftLeft(2).mod(this.curve.q); //compute S
	T1 = T4.square().mod(this.curve.q);
	T1 = T1.subtract(T5.shiftLeft(1)).mod(this.curve.q); //compute x2
	T2 = T2.square().mod(this.curve.q);
	T2 = T2.shiftLeft(3).mod(this.curve.q); //compute T
	T5 = T5.subtract(T1).mod(this.curve.q);
	T5 = T4.multiply(T5).mod(this.curve.q);
	T2 = T5.subtract(T2).mod(this.curve.q); //compute y2
    return new ECPointFp(this.curve, this.curve.fromBigInteger(T1), this.curve.fromBigInteger(T2), T3);
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// TODO: modularize the multiplication algorithm
function pointFpMultiply(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();
    
    var countA=0;
    var countD=0;
    
    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice(); countD++;

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
	    R = R.add(hBit ? this : neg); countA++;
	}
    }
   
    //alert("normal: doublings "+ countD);
    //alert("normal: additions "+ countA);
    
    return R;
}

//Compute this*j + x*k (simultaneous multiplication)
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength();
  else
    i = k.bitLength();

  var w=2;
  var d=Math.ceil(i/w);
  var r=1<<w;
  var precomp=new Array();
  for(var ipc=0;ipc<r;ipc++){
	  if(ipc==0){ precomp[0]=this.curve.getInfinity();}
	  else {precomp[ipc*r]=precomp[(ipc-1)*r].add(this);}
	  for(var jpc=1;jpc<r;jpc++){
		  precomp[ipc*r+jpc]=precomp[ipc*r+jpc-1].add(x);
	  }
  }
  var R = this.curve.getInfinity();
  i=d;
  while(i > 0) {
    R = R.multiplyPowTwo(w); var tmp1=0, tmp2=0;
    for(var bit=1;bit<=w;bit++){
    	tmp1=tmp1|j.testBit(i*w-bit);
    	tmp2=tmp2|k.testBit(i*w-bit);
    	if(bit<w) {tmp1=tmp1<<1;tmp2=tmp2<<1;}
    }
    R=R.add(precomp[tmp1*r+tmp2]);
    --i;
  }  
  return R;
}

function pointFpMultiplyPowTwo(k) {
    var R=this;
    for(var i=0;i<k;i++){R=R.twice();}
    return R;
}

ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;
ECPointFp.prototype.multiplyPowTwo = pointFpMultiplyPowTwo;

// ----------------
// ECCurveFp

// constructor
function ECCurveFp(q,a,b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null);
    this.reducer = new Barrett(this.q);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if(other == this) return true;
    return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
}

function curveFpGetInfinity() {
    return this.infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

function curveReduce(x) {
    this.reducer.reduce(x);
}

// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
	return this.infinity;
    case 2:
    case 3:
	// point compression not supported yet
	return null;
    case 4:
    case 6:
    case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
			     this.fromBigInteger(new BigInteger(xHex, 16)),
			     this.fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
	return null;
    }
}

function curveFpEncodePointHex(p) {
	if (p.isInfinity()) return "00";
	var xHex = p.getX().toBigInteger().toString(16);
	var yHex = p.getY().toBigInteger().toString(16);
	var oLen = this.getQ().toString(16).length;
	if ((oLen % 2) != 0) oLen++;
	while (xHex.length < oLen) {
		xHex = "0" + xHex;
	}
	while (yHex.length < oLen) {
		yHex = "0" + yHex;
	}
	return "04" + xHex + yHex;
}

ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.reduce = curveReduce;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
ECCurveFp.prototype.encodePointHex = curveFpEncodePointHex;
