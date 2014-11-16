<?php
require dirname(__FILE__) . '/userkit.class.php';
$userKit = new userKit();

if ( $login = $userKit->login( 'admin', 'aaa', false ) ) {
    echo 'Login good!';
} else {
    echo $userKit->error;
}

$userKit->debug( $userKit );
?>