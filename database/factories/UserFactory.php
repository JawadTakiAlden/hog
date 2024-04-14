<?php

namespace Database\Factories;

use App\Types\UserType;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\User>
 */
class UserFactory extends Factory
{
    protected static ?string $password;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'full_name' => fake()->firstName() . ' ' . fake()->lastName(),
            'password' => static::$password ??= Hash::make('password'),
            'phone' => fake()->phoneNumber,
            'device_id' => Str::random(15),
            'type' => fake()->randomElement([UserType::TEACHER ,UserType::STUDENT , UserType::ADMIN ]),
            'is_blocked' => fake()->boolean(10)
        ];
    }

    /**
     * Indicate that the model's email address should be unverified.
     */
    public function unverified(): static
    {
        return $this->state(fn (array $attributes) => [
            'email_verified_at' => null,
        ]);
    }
}
