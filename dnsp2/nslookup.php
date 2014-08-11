<?php
//error_reporting(E_ALL & ~E_NOTICE); 
//< //$arr = array( $mc->get("foo"), $mc->get("bar") ); 

//Vary: Accept-Encoding, User-Agent
// --- SET HEADERS AND DETECT CACHE CONTROL PRESENCE/EXPIRATION.
session_cache_limiter('public'); //This stop php’s default no-cache
session_cache_expire(1800); // Optional expiry time in minutes
header("Connection: keep-alive");
header("Cache-control: public, max-age=1800, s-maxage=1800");
$host = rtrim($_GET["host"],'.');

//// FOR HTTP-PROXY ACCELERATED CACHING
//header("Location: http://" . $host);
$lastModified=filemtime(__FILE__);
$etagFile = md5_file(__FILE__);

//get the HTTP_IF_MODIFIED_SINCE header if set
$ifModifiedSince=(isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) ? $_SERVER['HTTP_IF_MODIFIED_SINCE'] : false);

//get the HTTP_IF_NONE_MATCH header if set (etag: unique file hash)
$etagHeader=(isset($_SERVER['HTTP_IF_NONE_MATCH']) ? trim($_SERVER['HTTP_IF_NONE_MATCH']) : false);

//set last-modified header
header("Last-Modified: ". gmdate("D, d M Y H:i:s", $lastModified) ." GMT");
//set etag-header
header("Etag: $etagFile");

//check if page has changed. If not, send 304 and exit
if (@strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE'])==$lastModified || $etagHeader==$etagFile )
{
       header("HTTP/1.1 304 Not Modified");
       //exit;
}
//echo "This page was last modified: ".date("d.m.Y H:i:s",time())."</br>\n";
//echo "Last-Modified: ".gmdate("D, d M Y H:i:s", $lastModified)." GMT";

if (isSet($_GET["host"]) && isSet($_GET["type"])) {
	$type = $_GET["type"];
 	//DNS_A, DNS_CNAME, DNS_HINFO, DNS_MX, DNS_NS, DNS_PTR, DNS_SOA, DNS_TXT, DNS_AAAA, DNS_SRV, DNS_NAPTR, DNS_A6, DNS_ALL or DNS_ANY.
	//print_r(checkdnsrr('8.8.8.8'));
        //$result = dns_get_record($host, DNS_ALL, $authns, $addtl);
        if ($_GET["type"] == "ALL"){
                $result = dns_get_record($host, DNS_ALL, $authns, $addtl);
                print_r($result);
                print_r($authns);
                print_r($addtl);
        }
        if ($_GET["type"] == "PTR"){
       //         $result = checkdnsrr($host);
                $result = dns_get_record($host, DNS_PTR, $authns, $addtl);
                //$result = checkdnsrr($host);
                print_r($result);
                print_r($authns);
                print_r($addtl);
                //$ccc = sizeof($result);
                //print $result[rand(0,$ccc-1)][mname];
        }
        if ($_GET["type"] == "SOA"){
                $result = dns_get_record($host, DNS_SOA, $authns, $addtl);
                $ccc = sizeof($result);
                print $result[rand(0,$ccc-1)][mname];
	}
	if ($_GET["type"] == "MX"){
		$res = (dns_get_record($host, DNS_MX, $authns, $addtl)) or print '0.0.0.0';
		$ccc = sizeof($res);
		$result = $res[rand(0,$ccc-1)][target];
		print $result;
		//$r2 = dns_get_record($h2, DNS_A, $authns, $addtl);
		//$ddd = sizeof($r2);
		//print $r2[rand(0,$ddd-1)][ip];
	}
        if ($_GET["type"] == "NS"){
                $result = dns_get_record($host, DNS_NS, $authns, $addtl);
		$ccc = sizeof($result);
		print $result[rand(0,$ccc-1)][target];
        }
        if ($_GET["type"] == "A"){
                $result = (dns_get_record($host, DNS_A, $authns, $addtl)) or print '0.0.0.0';
		$ccc = sizeof($result);
		print $result[rand(0,$ccc-1)][ip];
		//print_r(array_keys($result[0]));
        }
        if ($_GET["type"] == "CNAME"){
                $res = dns_get_record($host, DNS_CNAME, $authns, $addtl);
		$ccc = sizeof($res);
		$result = $res[rand(0,$ccc-1)][target];
		print $result;
		//$r2 = dns_get_record($h2, DNS_A, $authns, $addtl);
		//echo $result[0][class];
		//echo $result[0][ttl];
        }
} else {
	if (isSet($_GET["host"])) {
		$host = rtrim($_GET["host"]);
                //$result = dns_get_record($host, DNS_NS, $authns, $addtl);
                $result = (dns_get_record($host, DNS_A, $authns, $addtl)) or print '0.0.0.0';
                $ccc = sizeof($result);
                print $result[rand(0,$ccc-1)][ip];
	} else {
		print '0.0.0.0';
	}
}
//        if ($ip != $host) die ($ip);
//        $ip = gethostbyname($host);
//        $mx = getmxrr($host);

?>

