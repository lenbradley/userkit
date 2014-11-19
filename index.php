<?php
require dirname(__FILE__) . '/userkit.class.php';
$userkit = new userKit();

if ( ! empty( $_POST ) ) {
    if ( isset( $_POST['login'] ) ) {
        $login = $userkit->login( $_POST['username'], $_POST['password'] );

        if ( $login == false ) {
            $login_error = $userkit->error;
        }
    }
    
    if ( isset( $_POST['logout'] ) ) {
        $userkit->logout();
    }
}
?>

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
</from>
<?php endif; ?>