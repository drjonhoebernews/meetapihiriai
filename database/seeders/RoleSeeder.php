<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;

class RoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $roles = [
            'admin',               // Yönetici
            'accounting',          // Muhasebe
            'dealer',              // Bayi
            'support',             // Destek
            'customer',            // Müşteri
            'applicant',           // Başvuru yapmış kişi
        ];


        foreach ($roles as $role) {
            if (!Role::where('name', $role)->exists()) {
                Role::create(['name' => $role, 'guard_name' => 'api']);
            }
        }

        $this->command->info('Roller başarıyla eklendi!');
    }
}
