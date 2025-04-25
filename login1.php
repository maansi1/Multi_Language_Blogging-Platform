<?php
// Initialize the session
session_start();

// Redirect to welcome page if already logged in
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    header("location: after_login.php");
    exit;
}

// Include config
require_once "config.php";

// Initialize variables
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";

// Handle form submissions
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $form_type = $_POST["form_type"];

    if ($form_type === "login") {
        // LOGIN LOGIC
        if (empty(trim($_POST["username"]))) {
            $username_err = "Please enter username.";
        } else {
            $username = trim($_POST["username"]);
        }

        if (empty(trim($_POST["password"]))) {
            $password_err = "Please enter your password.";
        } else {
            $password = trim($_POST["password"]);
        }

        if (empty($username_err) && empty($password_err)) {
            $sql = "SELECT id, username, password FROM users WHERE username = ?";
            if ($stmt = mysqli_prepare($link, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $param_username);
                $param_username = $username;

                if (mysqli_stmt_execute($stmt)) {
                    mysqli_stmt_store_result($stmt);
                    if (mysqli_stmt_num_rows($stmt) == 1) {
                        mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                        if (mysqli_stmt_fetch($stmt)) {
                            if (password_verify($password, $hashed_password)) {
                                $_SESSION["loggedin"] = true;
                                $_SESSION["id"] = $id;
                                $_SESSION["username"] = $username;
                                header("location: after_login.php");
                                exit;
                            } else {
                                $password_err = "Invalid password.";
                            }
                        }
                    } else {
                        $username_err = "No account found with that username.";
                    }
                } else {
                    echo "Oops! Something went wrong. Please try again later.";
                }
                mysqli_stmt_close($stmt);
            }
        }
    }

    if ($form_type === "register") {
        // REGISTRATION LOGIC
        if (empty(trim($_POST["username"]))) {
            $username_err = "Please enter a username.";
        } else {
            $sql = "SELECT id FROM users WHERE username = ?";
            if ($stmt = mysqli_prepare($link, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $param_username);
                $param_username = trim($_POST["username"]);

                if (mysqli_stmt_execute($stmt)) {
                    mysqli_stmt_store_result($stmt);
                    if (mysqli_stmt_num_rows($stmt) == 1) {
                        $username_err = "This username is already taken.";
                    } else {
                        $username = trim($_POST["username"]);
                    }
                } else {
                    echo "Oops! Something went wrong. Please try again later.";
                }
                mysqli_stmt_close($stmt);
            }
        }

        if (empty(trim($_POST["password"]))) {
            $password_err = "Please enter a password.";
        } elseif (strlen(trim($_POST["password"])) < 6) {
            $password_err = "Password must have at least 6 characters.";
        } else {
            $password = trim($_POST["password"]);
        }

        if (empty(trim($_POST["confirm_password"]))) {
            $confirm_password_err = "Please confirm password.";
        } else {
            $confirm_password = trim($_POST["confirm_password"]);
            if (empty($password_err) && ($password != $confirm_password)) {
                $confirm_password_err = "Passwords do not match.";
            }
        }

        if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {
            $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
            if ($stmt = mysqli_prepare($link, $sql)) {
                mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
                $param_username = $username;
                $param_password = password_hash($password, PASSWORD_DEFAULT);

                if (mysqli_stmt_execute($stmt)) {
                    header("location: login1.php");
                    exit;
                } else {
                    echo "Something went wrong. Please try again later.";
                }
                mysqli_stmt_close($stmt);
            }
        }
    }

    mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login Register Form</title>
    <link href='https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css' rel='stylesheet'>
    <link rel="stylesheet" href="stylelogin.css">
    <style>
        .error { color: red; font-size: 0.9em; }
    </style>
</head>
<body>

<div class="wrapper">
    <span class="rotate-bg"></span>
    <span class="rotate-bg2"></span>

    <!-- Login Form -->
    <div class="form-box login">
        <h2 class="title animation" style="--i:0; --j:21">Login</h2>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <input type="hidden" name="form_type" value="login">

            <div class="input-box animation" style="--i:1; --j:22">
                <input type="text" name="username" required>
                <label>Username</label>
                <i class='bx bxs-user'></i>
                <span class="error"><?php echo $username_err; ?></span>
            </div>

            <div class="input-box animation" style="--i:2; --j:23">
                <input type="password" name="password" required>
                <label>Password</label>
                <i class='bx bxs-lock-alt'></i>
                <span class="error"><?php echo $password_err; ?></span>
            </div>

            <button type="submit" class="btn animation" style="--i:3; --j:24">Login</button>

            <div class="linkTxt animation" style="--i:5; --j:25">
                <p>Don't have an account? <a href="#" class="register-link">Sign Up</a></p>
            </div>
        </form>
    </div>

    <div class="info-text login">
        <h2 class="animation" style="--i:0; --j:20">Welcome!</h2>
        <p class="animation" style="--i:1; --j:21">Multi Language Blogging Platform</p>
    </div>

    <!-- Register Form -->
    <div class="form-box register">
        <h2 class="title animation" style="--i:17; --j:0">Sign Up</h2>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <input type="hidden" name="form_type" value="register">

            <div class="input-box animation" style="--i:18; --j:1">
                <input type="text" name="username" required>
                <label>Username</label>
                <i class='bx bxs-user'></i>
                <span class="error"><?php echo $username_err; ?></span>
            </div>

            <div class="input-box animation" style="--i:19; --j:2">
                <input type="password" name="password" required>
                <label>Password</label>
                <i class='bx bxs-lock-alt'></i>
                <span class="error"><?php echo $password_err; ?></span>
            </div>

            <div class="input-box animation" style="--i:20; --j:3">
                <input type="password" name="confirm_password" required>
                <label>Confirm Password</label>
                <i class='bx bxs-lock-alt'></i>
                <span class="error"><?php echo $confirm_password_err; ?></span>
            </div>

            <button type="submit" class="btn animation" style="--i:21;--j:4">Sign Up</button>

            <div class="linkTxt animation" style="--i:22; --j:5">
                <p>Already have an account? <a href="#" class="login-link">Login</a></p>
            </div>
        </form>
    </div>

    <div class="info-text register">
        <h2 class="animation" style="--i:17; --j:0;">Multi Language Blogging</h2>
        <p class="animation" style="--i:18; --j:1;">Personalize your blogging experience</p>
    </div>
</div>

<script src="scriptlogin.js"></script>
</body>
</html>
