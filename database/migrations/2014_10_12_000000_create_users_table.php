<?php

use App\Types\UserType;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('full_name');
            $table->string('phone')->unique();
            $table->string('image')->nullable();
            $table->string('password');
            $table->string('device_id')->nullable()->unique();
            $table->string('device_notification_id')->nullable()->unique();
            $table->boolean('is_blocked')->default(false);
            $table->string('type')->default(UserType::STUDENT);
            $table->index(['phone']);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
