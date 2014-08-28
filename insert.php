<?php

$dbname="testdb"; 
$dbhost="localhost";
$dbuser="testuser";
$dbpass="geheim"; 
$dbconnection = mysql_connect($dbhost, $dbuser, $dbpass) or die(mysql_error());

mysql_select_db($dbname,$dbconnection) or die(mysql_error()); 

$Q_x = $_POST['pub_x']; $Q_x = trim($Q_x);
$Q_y = $_POST['pub_y']; $Q_y = trim($Q_y);
$m = $_POST['hashed_input']; $m = trim($m);
$R_x = $_POST['R_x']; $R_x = trim($R_x);
$R_y = $_POST['R_y']; $R_y = trim($R_y);
$s = $_POST['s']; $s = trim($s);
if(isset($_POST['curve'])){
	switch ($_POST['curve']){
		case 'brainpoolP256r1': $curve = "brainpoolP256r1";break;
		case 'brainpoolP512r1': $curve = "brainpoolP512r1";break;
		case 'brainpoolP512t1': $curve = "brainpoolP512t1";break;
	}
}


if(empty($Q_x)||empty($Q_y)||empty($m)||empty($R_x)||empty($R_y)||empty($s)){
	die('Signature incomplete');
}
	
$abfrage="INSERT INTO signatures (Q_x, Q_y, m, R_x, R_y, s, curve) 
	VALUES ('".$Q_x."','".$Q_y."','".$m."','".$R_x."','".$R_y."','".$s."','".$curve."')";
if (mysql_query($abfrage, $dbconnection)){
    print("Data successfully submitted!");
}else{
	die(mysql_error());
}

/*	$errormessage="Please fill out all fields.";
	echo "<script type='text/javascript' language='javascript'>";
	echo " alert('".$errormessage."')";
	echo "</script>"; 
*/

mysql_close($dbconnection);

?>  
