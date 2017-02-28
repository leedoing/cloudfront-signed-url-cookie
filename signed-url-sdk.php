<?php
require 'vendor/autoload.php'; // include autoloader of composer.
use Aws\CloudFront\CloudFrontClient;

function createSignedUrl($streamHostUrl, $resourceKey, $timeout){
$cloudFront = new Aws\CloudFront\CloudFrontClient([
    'region'  => 'ap-northeast-2',
    'version' => '2014-11-06'
]);
$streamHostUrl = 'http://d1e5lqevy0hhfg.cloudfront.net';
$resourceKey = 'test.mp4';
$url = $streamHostUrl . '/' . $resourceKey;
$expires = time() + $timeout;
$ip = $_SERVER['REMOTE_ADDR'] . "\/24";

$json = '{"Statement":[{"Resource":"'.$url.'","Condition":{"IpAddress":{"AWS:SourceIp":"'.$ip.'"},"DateLessThan":{"AWS:EpochTime":'.$expires.'}}}]}';
//$json = '{"Statement":[{"Resource":"'.$url.'","Condition":{"IpAddress":{"AWS:SourceIp":"218.236.80.0\/24"},"DateLessThan":{"AWS:EpochTime":'.$expires.'}}}]}';

$signedUrlCannedPolicy = $cloudFront->getSignedUrl([
    'url'         => $streamHostUrl . '/' . $resourceKey,
//  'expires'     => $expires, //Manual Policy
    'policy'      => $json, //Custom Policy
    'private_key' => '/home/ec2-user/pk-APKAICJI44KY7SDYRFQQ.pem',
    'key_pair_id' => 'APKAICJI44KY7SDYRFQQ'
]);
	return $signedUrlCannedPolicy;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
        <meta charset="utf-8" />
        <title>Signed URL Test</title>
</head>
<body>
        <div>
        <?php $signedUrl = createSignedUrl('http://d1e5lqevy0hhfg.cloudfront.net', 'test.mp4', 30);?>
                <?php echo $signedUrl ?>
        </div>

        <video controls autoplay>
                <source src="<?php echo $signedUrl ?>" type="video/mp4">
        </video>

</body>
</html>
