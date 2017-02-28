<?php
require 'vendor/autoload.php'; // include autoloader of composer.
use Aws\CloudFront\CloudFrontClient;

$cloudFront = new Aws\CloudFront\CloudFrontClient([
    'region'  => 'ap-northeast-2',
    'version' => '2014-11-06'
]);
$streamHostUrl = 'http://cf.leedoing.com';
$resourceKey = 'test.mp4';
$url = $streamHostUrl . "/" . $resourceKey;
$ip = $_SERVER['REMOTE_ADDR'] . "\/24";
//$url = 'http://ec2-52-78-189-144.ap-northeast-2.compute.amazonaws.com/*';
$expires = time() + 300;

$json = '{"Statement":[{"Resource":"'.$url.'","Condition":{"IpAddress":{"AWS:SourceIp":"'.$ip.'"},"DateLessThan":{"AWS:EpochTime":'.$expires.'}}}]}';
//$json = '{"Statement":[{"Resource":"'.$url.'","Condition":{"IpAddress":{"AWS:SourceIp":"218.236.84.40\/32"},"DateLessThan":{"AWS:EpochTime":'.$expires.'}}}]}';

$signedCookieCustomPolicy = $cloudFront->getSignedCookie([
   'url'         => $url,  //Manual Policy
//   'expires'     => $expires, //Manual Policy
  'policy'      => $json, //Custom Policy
    'private_key' => '/home/ec2-user/pk-APKAICJI44KY7SDYRFQQ.pem',
    'key_pair_id' => 'APKAICJI44KY7SDYRFQQ'
]);
?>

<!DOCTYPE html>
<html lang="en">
<head>
        <meta charset="utf-8" />
        <title>signed cookie Test</title>
</head>
<body>
	<?php
	foreach ($signedCookieCustomPolicy as $name => $value) {
	    setcookie($name, $value, 0, "", "leedoing.com", false, true);
	}
	print_r($signedCookieCustomPolicy);
	?>

        <video controls autoplay>
                <source src="http://cf.leedoing.com/test.mp4" type="video/mp4">
        </video>

	<img src="http://cf.leedoing.com/1_40.gif">

</body>
</html>
