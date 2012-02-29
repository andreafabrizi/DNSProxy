<?php

    if (isSet($_GET["host"]))
    {
        $host = $_GET["host"];
        $ip = gethostbyname($host);
        if ($ip != $host) die ($ip);
    }
    
    echo "0.0.0.0";
?>

