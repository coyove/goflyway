<?php

if (!array_key_exists("HTTP_X_FORWARDED_URL", $_SERVER)) {
    var_dump($_SERVER);
    die();
}

$dest = explode(",", $_SERVER['HTTP_X_FORWARDED_URL']);

if ($dest[1] == "dns") {
    $ip = gethostbyname($dest[0]);
    header("ETag: ". base64_encode($ip));
    die();
}

$fp = fsockopen($dest[0], (int)$dest[1], $errno, $errstr, 30);
if (!$fp)
{
    echo "$errstr ($errno)";
}
else
{
    $body = fopen("php://input", "r");

    while ($line = fgets($body, 128)) {
        fwrite($fp, $line, strlen($line));
    }
    
    flush();

    while (!feof($fp))
    {
        $chunk = fgets($fp, 4096);
        echo $chunk;
    }

    fclose($fp);
}
?>
