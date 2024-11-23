<?php
session_start();

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "secure_login";

// Crear conexión
$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar conexión
if ($conn->connect_error) {
    die("Conexión fallida " . $conn->connect_error);
}

// Función para registrar intentos fallidos
function logFailedAttempt($ip, $conn) {
    $stmt = $conn->prepare("INSERT INTO failed_attempts (ip_address, attempt_time) VALUES (?, NOW())");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $stmt->close();
}

// Función para verificar intentos fallidos
function isBlocked($ip, $conn) {
    $stmt = $conn->prepare("SELECT COUNT(*) as attempts FROM failed_attempts WHERE ip_address = ? AND attempt_time > (NOW() - INTERVAL 5 MINUTE)");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $result['attempts'] >= 3;
}

// Generar token CSRF si no existe
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $ip = $_SERVER['REMOTE_ADDR'];

    // Verificar si la IP está bloqueada
    if (isBlocked($ip, $conn)) {
        die("Demasiados intentos fallidos. Intenta nuevamente en 5 minutos.");
    }

    // Validar si el token CSRF está presente
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        logFailedAttempt($ip, $conn);
        die("Token de seguridad inválido.");
    }

    $email = $conn->real_escape_string($_POST['email']);
    $pass = $conn->real_escape_string($_POST['password']);

    // Verificar si el usuario existe
    $sql = "SELECT * FROM users WHERE email='$email'";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        // Verificar la contraseña
        if (password_verify($pass, $row['password'])) {
            echo "Inicio de sesión exitoso";
            // Crear sesión
            $_SESSION['id'] = $row['id'];
            unset($_SESSION['csrf_token']); // Regenerar token después de iniciar sesión
        } else {
            logFailedAttempt($ip, $conn);
            echo "Contraseña incorrecta.";
        }
    } else {
        logFailedAttempt($ip, $conn);
        echo "El usuario no existe.";
    }
}
?>

<form method="POST" action="login.php">
  <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
  <input type="text" name="email" placeholder="E-Mail" required><br>
  <input type="password" name="password" placeholder="Contraseña" required><br>
  <input type="submit" value="Iniciar sesión"><br>
</form>
  