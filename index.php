<?php
require dirname(__FILE__) . '/userkit.class.php';

$userkit = new userKit();

/*
if ( $userid = $userkit->addUser( 'admin', 'len@ideamktg.com', 'password' ) ) {
    echo '<p>' . $userid . ' created successfully!</p>';
} else {
    echo '<p>' . $userkit->error . '</p>';
}

*/

if ( $login = $userkit->login( 'admin', 'password', false ) ) {
    echo '<p>Login good!</p>';
} else {
    echo '<p>' . $userkit->error . '</p>';
}


$userkit->debug();
?>