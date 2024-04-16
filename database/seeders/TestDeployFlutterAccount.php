<?php

namespace Database\Seeders;

use App\Models\User;
use App\Types\UserType;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class TestDeployFlutterAccount extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        User::create([
            'full_name' => 'Tester',
            'phone' => '0999999999',
            'password' => 'test12345',
            'type' => UserType::TEST_DEPLOY,
        ]);
    }
}
