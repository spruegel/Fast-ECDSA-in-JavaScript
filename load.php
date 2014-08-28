<?php
	$dbname="testdb"; 
	$dbhost="localhost";
	$dbuser="testuser";
	$dbpass="geheim"; 
	$dbconnection = mysql_connect($dbhost, $dbuser, $dbpass) or die(mysql_error());

	$db = mysql_select_db($dbname,$dbconnection);

    if ($db){
    	$re = mysql_query("SELECT * FROM signatures");
	$i=0;
	while($daten = mysql_fetch_array($re)){
		$arr[$i]=$daten;					
		$i=$i+1;
	}
    }  
    echo json_encode($arr);
    mysql_close($dbconnection);
?> 
