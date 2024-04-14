<?php

use App\Types\LesionType;
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
        Schema::create('lesions', function (Blueprint $table) {
            $table->id();
            $table->string("title");
            $table->text('description')->nullable();
            $table->string('link');
            $table->integer('time');
            $table->boolean('is_visible')->default(false);
            $table->boolean("is_open")->default(false);
            $table->string('type')->default(LesionType::VIDEO);
            $table->foreignId("chapter_id")->references('id')->on('chapters')->onDelete('cascade');
            $table->index(['chapter_id' , 'is_visible']);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('lesions');
    }
};
