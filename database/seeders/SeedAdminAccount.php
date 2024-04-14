<?php

namespace Database\Seeders;

use App\Models\User;
use App\Types\UserType;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class SeedAdminAccount extends Seeder
{
    /**
     * Run the database seeds.
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
    }
}
