<?php

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
        Schema::create('exportable_files', function (Blueprint $table) {
            $table->id();
            $table->string('path');
            $table->integer('times_of_download')->default(0);
            $table->string('type_of_code');
            $table->string('courses_name')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('exportable_files');
    }
};
