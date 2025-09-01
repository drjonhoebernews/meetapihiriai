<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class ContactFormSubmitted extends Mailable
{
    use Queueable, SerializesModels;

    public array $data;

    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'Mesajınız Bize Ulaştı 🎉',
            to: [$this->data['email']],
        );
    }

    public function content(): Content
    {
        return new Content(
            view: 'emails.customer-confirm',
            with: ['data' => $this->data]
        );
    }

    public function attachments(): array
    {
        return [];
    }
}

