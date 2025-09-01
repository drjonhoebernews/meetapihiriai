<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>CMapps - Mesajınız Alındı</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px 0;">
    <tr>
        <td align="center">
            <table width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; overflow: hidden;">
                <!-- Header -->
                <tr>
                    <td style="background-color: #d7d9dc; padding: 20px; color: #ffffff; text-align: center;">
                        <h1 style="margin: 0; font-size: 22px;">CMapps Software LLC</h1>
                    </td>
                </tr>

                <!-- Body -->
                <tr>
                    <td style="padding: 30px; color: #333;">
                        <h2 style="font-size: 20px; margin-top: 0;">Merhaba {{ $data['name'] }},</h2>
                        <p style="font-size: 15px; line-height: 1.6;">
                            Mesajınızı başarıyla aldık. Ekibimiz en kısa sürede sizinle iletişime geçecektir.
                        </p>

                        <hr style="border: 0; height: 1px; background-color: #ddd; margin: 25px 0;">

                        <p style="font-size: 15px; margin-bottom: 5px;"><strong>Gönderdiğiniz Mesaj:</strong></p>
                        <div style="font-size: 14px; font-style: italic; color: #555; background-color: #f9f9f9; border-left: 4px solid #004080; padding: 10px 15px; margin-bottom: 30px;">
                            {{ $data['message'] }}
                        </div>

                        <p style="font-size: 14px;">İlginiz için teşekkür ederiz.</p>
                        <p style="font-size: 14px; margin-bottom: 0;">Saygılarımızla,</p>
                        <p style="font-size: 14px; font-weight: bold;">CMapps Destek Ekibi</p>
                    </td>
                </tr>

                <!-- Footer -->
                <tr>
                    <td style="background-color: #f0f0f0; padding: 20px; text-align: center; font-size: 12px; color: #888;">
                        © {{ date('Y') }} CMapps Software LLC. Tüm hakları saklıdır.
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>

</body>
</html>
