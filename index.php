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

    <footer class="my-5 pt-5 text-muted text-center text-small"></footer>
</div>

<script src="https://getbootstrap.com/docs/5.0/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
        crossorigin="anonymous"></script>

<script src="https://getbootstrap.com/docs/5.0/examples/checkout/form-validation.js"></script>
</body>
</html>

