<?php

// DNSP note: this script is kept for archive reasons.
// it is the original version of DNSP resolver, and 
// uses the gethostbyname PHP function, opposedly to
// the more modular PHP function dns_get_record

    if (isSet($_GET["host"]))
    {
        $host = $_GET["host"];
        $ip = gethostbyname($host);
        if ($ip != $host) die ($ip);
    }
    
    echo "$ip";
?>

