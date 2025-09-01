<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Spatie\Permission\Models\Role;

class AdminSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $adminRole = Role::firstOrCreate(['name' => 'admin']);

        $user = User::create([
            'id' => Str::uuid(),
            'username' => 'cmappsdck',
            'email' => 'dogancihatkayanews@gmail.com',
            'password' => Hash::make('2238drdr'),
            'cmappsID' => 'CMAPPS',
            'active' => true,
            'banned' => false,
            'email_verified_at' => now(),
        ]);
        $user->assignRole($adminRole);

    }
}
