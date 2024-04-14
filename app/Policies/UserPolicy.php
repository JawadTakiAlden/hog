<?php

namespace App\Policies;

use App\Models\User;
use App\Types\UserType;

class UserPolicy
{
    /**
     * Create a new policy instance.
     */
    public function __construct()
    {
        //
    }

    public function update_profile(User $userWantUpdate , User $userShouldUpdate){
        return intval($userWantUpdate->id) === intval($userShouldUpdate->id)
            ||
            (
                strval($userWantUpdate->type) === UserType::ADMIN
                && strval($userShouldUpdate->type) !== UserType::ADMIN
            );
    }

    public function course_of_user(User $authUser , User $user){
        return intval($authUser->id) === intval($user->id)
            || strval($authUser->type) === UserType::ADMIN ;
    }

    public function get_profile_of_user(User $authUser , User $hasProfile){
        return intval($authUser->id) === intval($hasProfile->id)
            || strval($authUser->type) === UserType::ADMIN ;
    }

    public function login_admin(User $authuser , User $user){
        return strval($user->type) === UserType::ADMIN;
    }
}
