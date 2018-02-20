<?php

// DNSP note: this script is used for testing/dev only
// and uses the dns_get_record PHP function

if ($_GET['dn'])
{
	$lookupData = dns_get_record($_GET['dn'],DNS_ANY,$authns,$addtl);
	if ($lookupData)
	{
		echo $lookupData[0]['ip'];
		echo '<pre>';
		echo 'ANY</br>';
		print_r($lookupData);
		echo 'AUTH</br>';
		print_r($authns);
		echo 'ADDITIONAL</br>';
		print_r($addtl);
		echo '</pre>';
	}
	else
		echo -100;
}
else
{
	echo -150;
}
?>
