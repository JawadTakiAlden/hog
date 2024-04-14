<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Lesion>
 */
class LesionFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'title' => fake()->unique()->sentence(),
            'link' => fake()->url,
            'is_visible' => fake()->boolean(),
            'is_open' => fake()->boolean(10),
            'type' => fake()->randomElement(['pdf' , 'video']),
            'chapter_id' => fake()->numberBetween(1,1000),
            'time' => fake()->numberBetween(1,45)
        ];
    }
}
