<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Course>
 */
class CourseFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->name,
            'image' => '',
            'is_visible' => fake()->boolean(90),
            'is_open' => fake()->boolean(10),
            'telegram_channel_link' => 'https://t.me/'.fake()->word
        ];
    }
}
