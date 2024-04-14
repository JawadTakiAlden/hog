<?php

namespace App\Providers;

// use Illuminate\Support\Facades\Gate;
use App\Models\User;
use App\Policies\UserPolicy;
use App\Types\UserType;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The model to policy mappings for the application.
     *
     * @var array<class-string, class-string>
     */
    protected $policies = [
        User::class => UserPolicy::class
    ];

    /**
     * Register any authentication / authorization services.
     */
    public function boot(): void
    {
        $this->registerPolicies();
        Gate::define('update_profile' , [UserPolicy::class , 'update_profile']);
        Gate::define('get_courses_of_user' , [UserPolicy::class , 'course_of_user']);
        Gate::define('get_profile_of_user' , [UserPolicy::class , 'get_profile_of_user']);
        Gate::define('login_admin' , [UserPolicy::class , 'login_admin']);
    }
}
