<?php

namespace Database\Factories;

use App\Models\CourseTeacher;
use App\Models\User;
use App\Types\UserType;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\CourseTeacher>
 */
class CourseTeacherFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {

        return [
            'course_id' => fake()->numberBetween(1,80),
            'teacher_id' => fake()->numberBetween(1,500)
        ];
    }
}
