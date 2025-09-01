<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Şifre Sıfırlama</title>
    <style>
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            background-color: #f4f4f7;
            color: #51545e;
            margin: 0;
            padding: 0;
        }
        .email-wrapper {
            width: 100%;
            padding: 20px;
            background-color: #f4f4f7;
        }
        .email-content {
            max-width: 600px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            padding: 40px;
        }
        .email-header {
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 25px;
            color: #1a1a1a;
        }
        .email-body {
            font-size: 16px;
            line-height: 1.6;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            margin-top: 20px;
            background-color: #2563eb;
            color: #ffffff !important;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
        }
        .email-footer {
            margin-top: 30px;
            font-size: 12px;
            color: #888;
            text-align: center;
        }
        .link-text {
            word-break: break-all;
            font-size: 14px;
            color: #2563eb;
        }
    </style>
</head>
<body>
<div class="email-wrapper">
    <div class="email-content">
        <div class="email-header">Şifre Sıfırlama Talebiniz</div>

        <div class="email-body">
            <p>Merhaba,</p>
            <p>Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın. Bu bağlantı yalnızca <strong>1 saat</strong> geçerlidir.</p>

            <p style="text-align: center;">
                <a href="{{ $link }}" class="button">Şifreyi Sıfırla</a>
            </p>

            <p>Eğer bu isteği siz yapmadıysanız, bu e-postayı göz ardı edebilirsiniz. Hesabınız güvende kalacaktır.</p>

            <p class="link-text">Doğrudan bağlantı: <br>{{ $link }}</p>
        </div>

        <div class="email-footer">
            &copy; {{ now()->year }} Entekas Teknoloji. Tüm hakları saklıdır.
        </div>
    </div>
</div>
</body>
</html>
