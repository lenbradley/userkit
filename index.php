<?php
require dirname(__FILE__) . '/userkit.class.php';
$userkit = new userKit();

if ( isset( $_POST['login'] ) ) {

    $remember = ( isset( $_POST['remember'] ) && $_POST['remember'] == 1 ) ? true : false;
    $login = $userkit->login( $_POST['username'], $_POST['password'], $remember );

    if ( $login == false ) {
        $login_error = $userkit->error;
    }
}
    
if ( isset( $_POST['logout'] ) ) {
    $userkit->logout();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>userKit Example</title>
</head>
<body>
    <?php if ( $userkit->isLoggedIn() ) : ?>
    <form action="" method="post">
        <p>You are logged in as <strong><?php echo $userkit->username; ?></strong></p>
        <input type="submit" name="logout" value="Logout">
    </from>
    <?php else : ?>
    <form action="" method="post">
        <?php if ( isset( $login_error ) ) : ?>
        <p><?php echo $login_error; ?></p>
        <?php endif; ?>
        <label>Username</label><br>
        <input type="text" name="username" value=""><br>
        <label>Password</label><br>
        <input type="password" name="password" value=""><br>    
        <input type="submit" name="login" value="Login">
        <label><input type="checkbox" name="remember" value="1"> Remember</label>
    </form>
    <?php endif; ?>
</body>
</html>