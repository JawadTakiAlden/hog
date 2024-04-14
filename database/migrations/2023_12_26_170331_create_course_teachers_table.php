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
        Schema::create('course_teachers', function (Blueprint $table) {
            $table->id();
            $table->foreignId("course_id")->references('id')->on('courses')->onDelete('cascade');
            $table->foreignId("teacher_id")->references('id')->on('users')->onDelete('cascade');
            $table->index(['course_id' , 'teacher_id']);
            $table->timestamps();
        });
    }
    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('course_teachers');
    }
};
