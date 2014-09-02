<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
	<head>
		<title>ECDSA</title>
		 
		<script type="text/javascript" src="jsbn/ec_mod.js"></script>
		<script type="text/javascript" src="jsbn/jsbn.js"></script>
		<script type="text/javascript" src="jsbn/jsbn2_mod.js"></script>
		<script type="text/javascript" src="jsbn/prng4.js"></script>
		<script type="text/javascript" src="jsbn/rng.js"></script>
		<script type="text/javascript" src="jsbn/sec_mod.js"></script>

		<script type="text/javascript" src="crypto-js/crypto.js"></script>
		<script type="text/javascript" src="crypto-js/sha256.js"></script>
		<script type="text/javascript" src="crypto-js/util.js"></script>

		<script type="text/javascript" src="ecdsa/fast_ecdsa.js"></script>
		<script type="text/javascript" src="ecdsa/signature.js"></script>
		
		<script type="text/javascript" src="jQuery/jquery.min.js"></script>		

		<script type="text/javascript" src="precomputation/precomp.js"></script>
		<script type="text/javascript">
			var usedCurve = "brainpoolP512t1";	
			
			function do_init() {
				if(document.f.p.value.length == 0) set_ec_params(usedCurve);
			}
			
			function do_status(s) {
				document.f.status.value = s;
			}
			
			function get_curve() {
				return new ECCurveFp(new BigInteger(document.f.p.value, 16),
					new BigInteger(document.f.a.value, 16),
					new BigInteger(document.f.b.value, 16));
			}

			function get_G(curve) {
				return new ECPointFp(curve,
					curve.fromBigInteger(new BigInteger(document.f.G_x.value, 16)),
					curve.fromBigInteger(new BigInteger(document.f.G_y.value, 16)));
			}
			
			function clear_signature_fields(){
				document.f.priv_key.value ="";
				document.f.pub_x.value="";
				document.f.pub_y.value="";
				document.f.hashed_input.value="";
				document.f.R_x.value="";
				document.f.R_y.value="";
				document.f.s.value="";
			}

			function set_ec_params(name) {
				var c = getSECCurveByName(name);
				document.f.p.value = c.getCurve().getQ().toString(16);
				document.f.a.value = c.getCurve().getA().toBigInteger().toString(16);
				document.f.b.value = c.getCurve().getB().toBigInteger().toString(16);
				document.f.G_x.value = c.getG().getX().toBigInteger().toString(16);
				document.f.G_y.value = c.getG().getY().toBigInteger().toString(16);
				document.f.q.value = c.getN().toString(16)
				GLOBAL_precomp.length=0;clear_signature_fields();
				do_status("Using " + name + " EC parameters");
			}
			
			function getBigRandom(limit) {
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
			}
			
			function generatePrivateKey(){
				var q = new BigInteger(document.f.q.value, 16);
				var before = new Date();
				document.f.priv_key.value=getBigRandom(q).toString(16);
				var after = new Date();
				do_status("Private key in " + (after - before) + "ms.");
			}
			
			function generatePublicKey(){
				if(GLOBAL_precomp.length==0){
					document.f.pub_x.value="";document.f.pub_y.value="";
					alert("no precomputed data");return;
				} else if(document.f.priv_key.value.length==0){
					alert("no private key");return;
				}
				var w = 4;
				var curve = get_curve();
				var q = new BigInteger(document.f.q.value, 16);
				var priv = new BigInteger(document.f.priv_key.value, 16);
				var N = new ECPointFp(curve);
				var before = new Date();
				N = ecpComb2Mult(priv,N,w,GLOBAL_precomp,q.bitLength());
				var after = new Date();
				
				if(N.isInfinity()){
					document.f.pub_x.value="0";
					document.f.pub_y.value="0";
				}
				else{
					document.f.pub_x.value = N.getX().toBigInteger().toString(16);
					document.f.pub_y.value = N.getY().toBigInteger().toString(16);
				}			
				do_status("Public key in " + (after - before) + "ms.");
			}
			
			function hash(){
				if (document.f.input.value.length == 0) {
					alert("no input text - nothing to hash.");
					return;
				}		
				var before = new Date();
				var hash = Crypto.SHA256(document.f.input.value);
				var after = new Date();
				
				document.f.hashed_input.value = hash;			
				do_status("plaintext hashed in " + (after - before) + "ms.");
			}
			
			function sign(){			
				if (document.f.hashed_input.value.length == 0) {
					alert("no hash - nothing to sign.");
					return;
				}else if(document.f.pub_x.value.length == 0 || document.f.pub_y.value.length == 0){
					alert("no public key"); return;
				}	
				var hash = Crypto.util.hexToBytes(document.f.hashed_input.value);
				var priv = new BigInteger(document.f.priv_key.value, 16);
				
				var before = new Date();
				var signature = ECDSA.sign(hash, priv);	
				var after = new Date();
				
				document.f.R_x.value = signature[0].getX().toBigInteger().toString(16);
				document.f.R_y.value = signature[0].getY().toBigInteger().toString(16);
				document.f.s.value = signature[1].toString(16);		
				do_status("plaintext hash digitally signed in " + (after - before) + "ms.");
			}
			
			function verify(){
				if (document.f.R_x.value.length == 0 || document.f.R_y.value.length == 0 || document.f.s.value.length == 0) {
					alert("no signature - nothing to verify.");
					return;
				}
				var curve = get_curve();			
				var hash = Crypto.util.hexToBytes(document.f.hashed_input.value);
				var sig = [new ECPointFp(curve,
					curve.fromBigInteger(new BigInteger(document.f.R_x.value, 16)),
					curve.fromBigInteger(new BigInteger(document.f.R_y.value, 16))),
					new BigInteger(document.f.s.value,16)];
				var pubkey = new ECPointFp(
					getSECCurveByName(usedCurve).curve, 
					new ECFieldElementFp(new BigInteger(document.f.p.value, 16), new BigInteger(document.f.pub_x.value, 16)), 
					new ECFieldElementFp(new BigInteger(document.f.p.value, 16), new BigInteger(document.f.pub_y.value, 16)),
					null
				);
				var before = new Date();
				var ok = ECDSA.verify(hash, sig, pubkey) ? "OK" : "Error";
				var after = new Date();			
				do_status("digital signature verified in " + (after - before) + "ms. Result: " + ok);
			}
			
			var GLOBAL_precomp = new Array();
			function precompute(){
				var curve = get_curve();
				var G = get_G(curve);
				var q = new BigInteger(document.f.q.value, 16);
				var w = 4;
				
				var before = new Date();
				GLOBAL_precomp=precomputeComb2(G,w,curve,q.bitLength());
				var after = new Date();
				
				do_status("Precomputation performed in " + (after - before) + "ms.");
			}

			var GLOBAL_signature = new Array();
			function load(){
		    	$.ajax({                                      
		      		url: 'load.php',                           
			      	data: "",                        			                  
			      	dataType: 'json',                     
			      	success: function(data){      
						if(data==null){
							alert("database is empty");return;
						}else if(usedCurve!=data[0][7]){
							usedCurve=data[0][7];
							set_ec_params(usedCurve);
						}
						for(var i=0;i<data.length;i++){
							GLOBAL_signature[i]=new ECSignature(data[i]);
							if(data[i][7]!=usedCurve){
								alert("Error: signatures in batch are signed under different curve parameters.");
								GLOBAL_signature.length=0; return;
							}	
						}
						GLOBAL_signature.length=data.length;
						do_status(data.length + " signatures loaded ");
					} 
			    });
		  	} 

			function batchSingle(){
				if(GLOBAL_signature.length==0){
					alert("no signatures loaded from the database");return;
				}
				for(var i=0;i<GLOBAL_signature.length;i++){
					if(!GLOBAL_signature[i].Q.getX().equals(GLOBAL_signature[0].Q.getX())){
						alert("signatures in database belong to different signers");
						return;
					}
				}
				var before = new Date();
				var ok = batchSingleSigner(GLOBAL_signature) ? "OK" : "Error";
				var after = new Date();

				var num = GLOBAL_signature.length;
				do_status("Batch total: "+(after - before) + " average: " + (after - before)/num +" Result: " + ok);
			}

			function batchMultiple(){
				if(GLOBAL_signature.length==0){
					alert("no signatures loaded from the database");return;
				}
				var before = new Date();
				var ok = batchMultipleSigner(GLOBAL_signature) ? "OK" : "Error";
				var after = new Date();

				var num = GLOBAL_signature.length;
				do_status("Batch total: "+(after - before) + " average: " + (after - before)/num +" Result: " + ok);
			}

			function single(){
				if(GLOBAL_precomp.length==0){
					alert("no precomputed data");return;
				}else if(GLOBAL_signature.length==0){
					alert("no signatures loaded from the database");return;
				}
				var i=0;var ok="";
				var num = GLOBAL_signature.length;
				var before = new Date();
				while(i<num && GLOBAL_signature[i].verify()){
					i++;
				}
				var after = new Date();
				if(i==num) ok="OK"; else ok="Error";
				do_status("Single total: "+(after - before) + " average: " + (after - before)/num +" Result: " + ok+" "+i);				
			}		
		</script>
		
		<style type="text/css">
			body {background-color:#FFFFCC;
			      margin-left:100px;}
			h1 {color:blue;}
		</style>
	</head>
	<body onload="do_init();">
		<h1>ECDSA</h1>		
		<p>
			<form name="f" action="insert.php" method="post">
			<p>
				Elliptic curve: y<sup>2</sup> = x<sup>3</sup> + ax + b mod p <br />
				<input type="radio" name="curve" value="brainpoolP256r1" onclick="usedCurve='brainpoolP256r1';set_ec_params(usedCurve);GLOBAL_signature.length=0;"> brainpoolP256r1<br>
				<input type="radio" name="curve" value="brainpoolP512r1" onclick="usedCurve='brainpoolP512r1';set_ec_params(usedCurve);GLOBAL_signature.length=0;"> brainpoolP512r1<br>
				<input type="radio" name="curve" value="brainpoolP512t1" onclick="usedCurve='brainpoolP512t1';set_ec_params(usedCurve);GLOBAL_signature.length=0;" checked="checked"> brainpoolP512t1
			</p>
			<table border="1">
				<tr>
					<td valign="top">
						<table border="0">
							<tr>
								<td>a<br><textarea name="a" cols="45" rows="4"></textarea></td>
								<td>b<br><textarea name="b" cols="45" rows="4"></textarea></td>
							</tr>
							<tr>
								<td>G<sub>x</sub><br><textarea name="G_x" cols="45" rows="4"></textarea></td>
								<td>G<sub>y</sub><br><textarea name="G_y" cols="45" rows="4"></textarea></td>
							</tr>
							<tr>
								<td>p (base field)<br><textarea name="p" cols="45" rows="4"></textarea></td>
								<td>q (order of group generated by G)<br><textarea name="q" cols="45" rows="4"></textarea></td>
							</tr>
							<tr>
								<td>
									<input type="button" value="precompute" onclick="precompute()"> (depends on G)
								</td>
								<td>
									Status<br><textarea name="status" cols="45" rows="4"></textarea>
								</td>
							</tr>
							<tr>
								<td>private key<br><textarea name="priv_key" cols="45" rows="4"></textarea></td>
								<td>
									<input type="button" value="private key" onclick="generatePrivateKey()"><br>
									<input type="button" value="public key" onclick="generatePublicKey()">
								</td>
							</tr>
							<tr>
								<td>public x-coord<br><textarea name="pub_x" cols="45" rows="4"></textarea></td>
								<td>public y-coord<br><textarea name="pub_y" cols="45" rows="4"></textarea></td>
							</tr>
						</table>
					</td>
					<td valign="top">
						<table border="0">
							<tr>
								<td>input<br><textarea name="input" cols="45" rows="4">user input</textarea></td>
								<td>hashed input<br><textarea name="hashed_input" cols="45" rows="4"></textarea></td>
							</tr>
							<tr>
								<td>
									<input type="button" value="hash" onclick="hash()"> <input type="button" value="sign" onclick="sign()"> <input type="button" value="verify" onclick="verify()">
								</td>
							</tr>
							<tr>
								<td>R<sub>x</sub><br><textarea name="R_x" cols="45" rows="4"></textarea></td>
								<td>R<sub>y</sub><br><textarea name="R_y" cols="45" rows="4"></textarea></td>
							</tr>
							<tr>
								<td>s<br><textarea name="s" cols="45" rows="4"></textarea></td>
								<td>
									<input type="submit" value="upload signature" /> (to database)<br>
									<input type="button" value="load signatures" onclick="load()"> (from database)
								</td>
							</tr>
							<tr>
								<td>
									Batch verification <br>	
									<input type="button" value="single signer" onclick="batchSingle()"><br>
									<input type="button" value="multiple signers" onclick="batchMultiple()"><br>
									<input type="button" value="individual verification" onclick="single()"> (no batch)
								</td>
							</tr>
						</table>
					</td>
				</tr>
			</table>
			</form>
		</p>
	</body>
</html>
