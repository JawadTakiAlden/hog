<?php

namespace Database\Seeders;

// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use App\Models\Category;
use App\Models\Chapter;
use App\Models\Course;
use App\Models\CourseCategory;
use App\Models\CourseTeacher;
use App\Models\CourseValue;
use App\Models\Lesion;
use App\Models\News;
use App\Models\User;
use App\Types\UserType;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        User::create([
            'full_name' => 'jawad taki aldeen',
            'phone' => '0948966979',
            'password' => 'jawad',
            'is_blocked' => false,
            'type' => UserType::ADMIN,
        ]);
        User::factory(500)->create();
        Category::factory(50)->create();
        News::factory(50)->create();
        Course::factory(80)->create();
        CourseTeacher::factory(300)->create();
        CourseValue::factory(300)->create();
        Chapter::factory(1000)->create();
        Lesion::factory(1000)->create();
        CourseCategory::factory(500)->create();
    }
}
