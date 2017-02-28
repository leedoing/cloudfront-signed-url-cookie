<?php
require 'vendor/autoload.php'; // include autoloader of composer.
use Aws\CloudFront\CloudFrontClient;
function createSignedURL($streamHostUrl, $resourceKey, $timeout){
	$keyPairId = "APKAICJI44KY7SDYRFQQ";
	
	$streamHostUrl = 'http://cf.leedoing.com';
	$resourceKey = 'test.mp4';
	$url = $streamHostUrl . "/" . $resourceKey;
	$expires = time() + 20; 
	$ip=$_SERVER["REMOTE_ADDR"] . "\/24";

//       $json = '{"Statement":[{"Resource":"'.$url.'","Condition":{"IpAddress":{"AWS:SourceIp":"218.236.82.0\/24"},"DateLessThan":{"AWS:EpochTime":'.$expires.'}}}]}';
	$json = '{"Statement":[{"Resource":"'.$url.'","Condition":{"IpAddress":{"AWS:SourceIp":"'.$ip.'"},"DateLessThan":{"AWS:EpochTime":'.$expires.'}}}]}';

	$fp=fopen("/home/ec2-user/pk-APKAICJI44KY7SDYRFQQ.pem", "r");
	$priv_key=fread($fp, 8192);
	fclose($fp);

	$key = openssl_get_privatekey($priv_key);
	if(!$key){
		echo "<p>Failed to load private key!</p>";
		return;
	}
	if(!openssl_sign($json, $signed_policy, $key, OPENSSL_ALGO_SHA1)){
		echo '<p>Failed to sign policy: '.opeenssl_error_string().'</p>';
		return;
	}

	$base64_signed_policy = base64_encode($signed_policy);

	$policy = strtr(base64_encode($json), '+=/', '-_~'); //Custom Policy

	$signature = str_replace(array('+','=','/'), array('-','_','~'), $base64_signed_policy);

	//Construct the URL
//	$signedUrl = $url.'?Expires='.$expires.'&Signature='.$signature.'&Key-Pair-Id='.$keyPairId; //Manual Policy
	$signedUrl = $url.'?Policy='.$policy.'&Signature='.$signature.'&Key-Pair-Id='.$keyPairId;   //Custom Policy
	
	return $signedUrl;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
        <meta charset="utf-8" />
        <title>Signed URL Test</title>
</head>
<body>
        <?php
//	setcookie("CloudFront-Expires=$expire; path=/; domain=leedoing.com; false, true");
	setcookie("CloudFront-Signature=$signature; path=/; domain=leedoing.com; false, true");
	setcookie("CloudFront-Key-Pair-Id=$keypairdid; path=/; domain=leedoing.com; false, true");
	setcookie("CloudFront-Policy=$policy; path=/; domain=leedoing.com; false, true");
        ?>

        <video controls autoplay>
                <source src="http://cf.leedoing.com/test.mp4" type="video/mp4">
        </video>

        <img src="http://cf.leedoing.com/1_40.gif">

</body>
</html>

