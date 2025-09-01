<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class ResetPasswordMail extends Mailable
{
    use Queueable, SerializesModels;

    public string $link;

    /**
     * @param string $token
     * @param string $email
     */
    public function __construct(
        public string $token,
        public string $email
    ) {
        $this->link = url("/api/v1/auth/reset-password?token={$this->token}&email={$this->email}");
    }

    /**
     * @return Envelope
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'Şifre Sıfırlama Bağlantısı'
        );
    }

    /**
     * @return Content
     */
    public function content(): Content
    {
        return new Content(
            view: 'emails.reset-password',
            with: ['link' => $this->link]
        );
    }

    /**
     * @return array
     */
    public function attachments(): array
    {
        return [];
    }
}
