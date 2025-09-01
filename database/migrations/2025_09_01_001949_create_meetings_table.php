<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('meetings', function (Blueprint $table) {
            $table->uuid('id')->primary();

            $table->string('link', 1024);
            $table->enum('type', ['meet', 'teams', 'zoom'])->index();
            $table->timestamp('start_at')->index();
            $table->timestamp('end_at')->nullable()->index();
            $table->string('record_path', 2048)->nullable();
            $table->json('log')->nullable();

            $table->timestamps();
            $table->softDeletes();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('meetings');
    }
};
