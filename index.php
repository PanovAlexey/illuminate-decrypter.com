<?php

ini_set('error_reporting', E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

class Encryption
{
    private string $cipher;
    private string $key;

    public function __construct(string $cipher, string $key)
    {
        $this->cipher = $cipher;
        $this->key = base64_decode($key);
    }

    public function encrypt($value, $serialize = true)
    {
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));

        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        $value = \openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher, $this->key, 0, $iv
        );

        if ($value === false) {
            throw new Exception('Could not encrypt the data.');
        }

        // Once we get the encrypted value we'll go ahead and base64_encode the input
        // vector and create the MAC for the encrypted value so we can then verify
        // its authenticity. Then, we'll JSON the data into the "payload" array.
        $mac = $this->hash($iv = base64_encode($iv), $value);

        $json = json_encode(compact('iv', 'value', 'mac'));

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    public function decrypt($payload, $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);
        $iv = base64_decode($payload['iv']);

        $decrypted = \openssl_decrypt(
            $payload['value'], $this->cipher, $this->key, 0, $iv
        );

        if ($decrypted === false) {
            throw new Exception('Could not decrypt the data. Some parameters are wrong.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    protected function getJsonPayload($payload)
    {
        $payload = json_decode(base64_decode($payload), true);

        if (!$this->validPayload($payload)) {
            throw new Exception('The payload is invalid.');
        }

        if (!$this->validMac($payload)) {
            throw new Exception('The MAC is invalid.');
        }

        return $payload;
    }

    protected function validMac(array $payload)
    {
        $calculated = $this->calculateMac($payload, $bytes = random_bytes(16));

        return hash_equals(
            hash_hmac('sha256', $payload['mac'], $bytes, true), $calculated
        );
    }

    protected function calculateMac($payload, $bytes)
    {
        return hash_hmac(
            'sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true
        );
    }

    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }

    protected function validPayload($payload)
    {
        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']) &&
            strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length($this->cipher);
    }
}

$keySize = $_REQUEST['key_size'] ?? null;
$secretKey = $_REQUEST['secret_key'] ?? null;
$sourceText = $_REQUEST['source_text'] ?? null;
$textForDecryption = $_REQUEST['text_for_decryption'] ?? null;
$resultEncryptedText = null;
$resultDecryptedText = null;
?>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">
    <meta name="generator" content="Hugo 0.84.0">
    <title>Illuminate decryption online</title>

    <!-- Bootstrap core CSS -->
    <link href="https://getbootstrap.com/docs/5.0/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">

    <!-- Favicons -->
    <link rel="apple-touch-icon" href="https://getbootstrap.com/docs/5.0/assets/img/favicons/apple-touch-icon.png"
          sizes="180x180">
    <link rel="icon" href="https://getbootstrap.com/docs/5.0/assets/img/favicons/favicon-32x32.png" sizes="32x32"
          type="image/png">
    <link rel="icon" href="https://getbootstrap.com/docs/5.0/assets/img/favicons/favicon-16x16.png" sizes="16x16"
          type="image/png">
    <link rel="manifest" href="https://getbootstrap.com/docs/5.0/assets/img/favicons/manifest.json">
    <link rel="mask-icon" href="https://getbootstrap.com/docs/5.0/assets/img/favicons/safari-pinned-tab.svg"
          color="#7952b3">
    <link rel="icon" href="https://getbootstrap.com/docs/5.0/assets/img/favicons/favicon.ico">
    <meta name="theme-color" content="#7952b3">

    <style>
        .bd-placeholder-img {
            font-size: 1.125rem;
            text-anchor: middle;
            -webkit-user-select: none;
            -moz-user-select: none;
            user-select: none;
        }

        @media (min-width: 768px) {
            .bd-placeholder-img-lg {
                font-size: 3.5rem;
            }
        }


    </style>

    <!-- Custom styles for this template -->
    <link href="https://getbootstrap.com/docs/5.0/examples/checkout/form-validation.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container">
    <main>
        <div class="py-1 text-center">
            <img class="d-block mx-auto mb-1"
                 src="https://avatars.githubusercontent.com/u/1721772?s=200&v=4"
                 alt="Laravel encryption" width="55">
            <h2>Illuminate decryption online</h2>
            <p class="lead">
                Advanced Encryption Standard(AES) is a symmetric encryption algorithm.
                AES is the industry standard as of now as it allows 128 bit and 256 bit encryption.
                Symmetric encryption is very fast as compared to asymmetric encryption and are used in systems such as
                database system. Following is an online tool to generate AES encrypted password and decrypt AES
                encrypted password.
                It provides two mode of encryption and decryption ECB and CBC mode. For more info on AES encryption
                visit this explanation on AES Encryption.
            </p>
            <p class="lead">
                Laravel uses the Illuminate package for encryption by default, so you can use this service to decrypt data from Laravel.
            </p>
        </div>

        <form class="row g-5">
            <?php
            if ($keySize && $secretKey) {
                try {
                    $encryptor = new Encryption('AES-' . $keySize . '-CBC', $secretKey);

                    if ($sourceText) {
                        $resultEncryptedText = $encryptor->encrypt($sourceText, false);
                    }

                    if ($textForDecryption) {
                        $resultDecryptedText = $encryptor->decrypt($textForDecryption, false);
                    }
                } catch (\Throwable $exception) {
                    ?>
                    <div class="alert alert-danger" role="alert">
                    An error has occurred: <?php echo $exception->getMessage(); ?>
                    </div><?php
                }
            }
            ?>
            <div class="col-md-12">
                <div class="row g-3">
                    <div class="col-6 mx-auto">
                        <label class="form-label">Key Size in Bits</label>
                        <select class="form-select" name="key_size" required="">
                            <option value="">Choose...</option>
                            <option <?php if (!empty($keySize) && $keySize == 128) echo ' selected '; ?>>128</option>
                            <option <?php if (!empty($keySize) && $keySize == 256) echo ' selected '; ?>>256</option>
                        </select>
                        <div class="invalid-feedback">
                            Please select a key size.
                        </div>
                    </div>
                </div>
                <br>
                <div class="row g-3">
                    <div class="col-6 mx-auto">
                        <label class="form-label">Enter secret key</label>
                        <input type="text" name="secret_key" class="form-control" placeholder="Enter secret key"
                               required="" value="<?php echo $_REQUEST['secret_key'] ?? '' ?>">
                        <div class="invalid-feedback">
                            Please enter secret key.
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-6">
                <h4 class="mb-3">Encryption</h4>
                <div class="row g-3">
                    <div class="col-12">
                        <label class="form-label">
                            Enter text to be encrypted
                        </label>
                        <textarea
                                class="form-control input-lg" rows="5"
                                name="source_text"
                                placeholder="Enter plain text to encryption"><?php echo $_REQUEST['source_text'] ?? '' ?></textarea>
                    </div>
                </div>
                <hr class="my-4">
                <button class="w-100 btn btn-primary btn-lg" type="submit">Encrypt</button>
                <div class="row g-3">
                    <div class="col-12">
                        <label class="form-label">
                            Encrypted result text
                        </label>
                        <textarea
                                readonly
                                class="form-control input-lg ng-pristine ng-valid ng-touched" rows="5"
                                placeholder="Encrypted result text"><?php echo $resultEncryptedText ?? '' ?></textarea>
                    </div>
                </div>
            </div>
            <div class="col-6">
                <h4 class="mb-3">Decryption</h4>
                <div class="row g-3">
                    <div class="col-12">
                        <label class="form-label">
                            Enter text to be decrypted
                        </label>
                        <textarea
                                class="form-control input-lg" rows="5"
                                placeholder="Enter cipher text to decrypt"
                                name="text_for_decryption"><?php echo $_REQUEST['text_for_decryption'] ?? '' ?></textarea>
                    </div>
                </div>

                <hr class="my-4">
                <button class="w-100 btn btn-primary btn-lg" type="submit">Decrypt</button>

                <div class="row g-3">
                    <div class="col-12">
                        <label class="form-label">
                            Decrypted result text
                        </label>
                        <textarea
                                readonly
                                class="form-control input-lg ng-pristine ng-valid ng-touched" rows="5"
                                placeholder="Decrypted result text"><?php echo $resultDecryptedText ?? '' ?></textarea>
                    </div>
                </div>
            </div>
        </form>
    </main>

    <div class="container">
        <footer class="d-flex flex-wrap justify-content-between align-items-center py-3 my-4 border-top">
            <div class="col-md-4 d-flex align-items-center">
                <a href="/" class="mb-3 me-2 mb-md-0 text-muted text-decoration-none lh-1">
                    <svg class="bi" width="30" height="24">
                        <use xlink:href="#bootstrap"></use>
                    </svg>
                </a>
                <span class="text-muted">© 2017–<?= date("Y") ?> Panov Alexey.</span>
            </div>

            <ul class="nav col-md-4 justify-content-end list-unstyled d-flex">
                <li class="ms-3"><a class="text-muted" href="https://codeblog.pro">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor"
                             class="bi bi-facebook" viewBox="0 0 16 16">
                            <path d="M16 8.049c0-4.446-3.582-8.05-8-8.05C3.58 0-.002 3.603-.002 8.05c0 4.017 2.926 7.347 6.75 7.951v-5.625h-2.03V8.05H6.75V6.275c0-2.017 1.195-3.131 3.022-3.131.876 0 1.791.157 1.791.157v1.98h-1.009c-.993 0-1.303.621-1.303 1.258v1.51h2.218l-.354 2.326H9.25V16c3.824-.604 6.75-3.934 6.75-7.951z"/>
                        </svg>
                    </a>
                </li>
                <li class="ms-3"><a class="text-muted" href="https://www.linkedin.com/in/codeblog/">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor"
                             class="bi bi-linkedin"
                             viewBox="0 0 16 16">
                            <path d="M0 1.146C0 .513.526 0 1.175 0h13.65C15.474 0 16 .513 16 1.146v13.708c0 .633-.526 1.146-1.175 1.146H1.175C.526 16 0 15.487 0 14.854V1.146zm4.943 12.248V6.169H2.542v7.225h2.401zm-1.2-8.212c.837 0 1.358-.554 1.358-1.248-.015-.709-.52-1.248-1.342-1.248-.822 0-1.359.54-1.359 1.248 0 .694.521 1.248 1.327 1.248h.016zm4.908 8.212V9.359c0-.216.016-.432.08-.586.173-.431.568-.878 1.232-.878.869 0 1.216.662 1.216 1.634v3.865h2.401V9.25c0-2.22-1.184-3.252-2.764-3.252-1.274 0-1.845.7-2.165 1.193v.025h-.016a5.54 5.54 0 0 1 .016-.025V6.169h-2.4c.03.678 0 7.225 0 7.225h2.4z"/>
                        </svg>
                    </a>
                </li>
                <li class="ms-3"><a class="text-muted" href="https://github.com/PanovAlexey">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor"
                             class="bi bi-github"
                             viewBox="0 0 16 16">
                            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
                        </svg>
                    </a></li>
                <li class="ms-3"><a class="text-muted" href="https://twitter.com/codeblog_pro">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor"
                             class="bi bi-twitter"
                             viewBox="0 0 16 16">
                            <path d="M5.026 15c6.038 0 9.341-5.003 9.341-9.334 0-.14 0-.282-.006-.422A6.685 6.685 0 0 0 16 3.542a6.658 6.658 0 0 1-1.889.518 3.301 3.301 0 0 0 1.447-1.817 6.533 6.533 0 0 1-2.087.793A3.286 3.286 0 0 0 7.875 6.03a9.325 9.325 0 0 1-6.767-3.429 3.289 3.289 0 0 0 1.018 4.382A3.323 3.323 0 0 1 .64 6.575v.045a3.288 3.288 0 0 0 2.632 3.218 3.203 3.203 0 0 1-.865.115 3.23 3.23 0 0 1-.614-.057 3.283 3.283 0 0 0 3.067 2.277A6.588 6.588 0 0 1 .78 13.58a6.32 6.32 0 0 1-.78-.045A9.344 9.344 0 0 0 5.026 15z"/>
                        </svg>
                    </a></li>
            </ul>
        </footer>
    </div>

</div>

<script src="https://getbootstrap.com/docs/5.0/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
        crossorigin="anonymous"></script>

<script src="https://getbootstrap.com/docs/5.0/examples/checkout/form-validation.js"></script>
</body>
</html>