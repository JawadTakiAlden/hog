<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\CreateUserRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Requests\UpdateUserRequest;
use App\Http\Resources\CourseResource;
use App\Http\Resources\InrolmentsResource;
use App\Http\Resources\UserResource;
use App\HttpResponse\HTTPResponse;
use App\Models\Course;
use App\Models\User;
use App\Types\UserType;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;

class UserController extends Controller
{

    use HTTPResponse;

    private function permissionDenide(){
        return $this->error(trans('messages.error.admin_permission') , 403);
    }

    public function profile(){
        try {
            return $this->success(UserResource::make(Auth::user()));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getUserProfile($userID){
        try {
            $user = HelperFunction::getUserById($userID);
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            if (Gate::denies('get_profile_of_user' , $user)){
                return $this->permissionDenide();
            }
            return $this->success(UserResource::make($user));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getTeacher(){
        try {
            $teacher = User::where('type' , UserType::TEACHER)->get();
            return $this->success(UserResource::collection($teacher));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getSpicialAccounts(){
        try {
            $accounts = User::whereNot('type' , UserType::STUDENT)->get();
            return $this->success(UserResource::collection($accounts));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function create(CreateUserRequest $request){
        $request->validated($request->only(['full_name', 'image' , 'phone', 'password', 'type']));
        try {
            $user = User::create($request->only(['full_name', 'image' , 'phone', 'password', 'type']));
            return $this->success(UserResource::make($user) , __('messages.user_controller.create'));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function updateProfile(UpdateUserRequest $request , $userID){
        try {
            $user = HelperFunction::getUserById($userID);
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            if (!Gate::allows('update_profile' , $user)){
                return $this->permissionDenide();
            }
            $user->update($request->only('full_name' , 'image'  , 'phone' , 'email'));
            return $this->success(UserResource::make($user) , __('messages.user_controller.update_profile'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }

    }


//    public function blockAccount($userID){
//        try {
//            $user = HelperFunction::getUserById($userID);
//            if (!$user){
//                return $this->error(trans('messages.user_not_found') , 404);
//            }
//            $user->update([
//                'is_blocked' => true,
//            ]);
//            return $this->success(UserResource::make($user), $user->full_name . ' blocked successfully');
//        }catch(\Throwable $th){
//            return $this->error($th->getMessage() , 500);
//        }
//
//    }

//    public function unBlockAccount($userID){
//        $user = HelperFunction::getUserById($userID);
//        if (!$user){
//            return $this->error('user you\'re trying to unblock , not found in our system' , 404);
//        }
//        try {
//            $user->update([
//                'is_blocked' => false,
//            ]);
//
//            return $this->success(UserResource::make($user) , $user->full_name . ' unblocked successfully');
//        }catch(\Throwable $th){
//            return $this->error($th->getMessage() , 500);
//        }
//    }


    public function resetPassword(ResetPasswordRequest $request , $userID){
        try {
            $user = HelperFunction::getUserById($userID);
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            $user->update([
                'password' => $request->new_password
            ]);
            return $this->success(UserResource::make($user) , __('messages.user_controller.reset_password'));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function switchBlockState($userID) {
        try {
            $user = HelperFunction::getUserById($userID);
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            if ($user->is_blocked === 'false'){
                $user->currentAccessToken()->delete();
            }
            $user->update([
                'is_blocked' =>  !$user->is_blocked
            ]);
            return $this->success(UserResource::make($user),  __('messages.user_controller.block_switch'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }

    }

    public function getStudents(){
        try {
            $users = User::where('type' , UserType::STUDENT)->get();
            return $this->success(UserResource::collection($users));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }


    public function getAllUser(){
        try {
            $users = User::orderBy('created_at' , 'desc')->get();
            return $this->success(UserResource::collection($users));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }


    public function getAllBlockedUser(){
        try {
            $users = User::where('type' , 'student')->where('is_blocked' , true)->get();
            return $this->success(UserResource::collection($users));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }

    }

    public function GetAllInrolnmentCourseForThis($userID){
        try {
            $user = HelperFunction::getUserById($userID);
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            return $this->success(InrolmentsResource::collection($user->inroledCorurses));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getAllUserThatSignInToThis($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID , ['students']);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            return $this->success(UserResource::collection($course->students));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function inrollnmentCourseOfUser($userID){
        try {
            $user = HelperFunction::getUserById($userID , ['inroledCorurses']);
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            if (Gate::denies('get_courses_of_user' , $user)){
                return $this->permissionDenide();
            }
            return $this->success(CourseResource::collection($user->inroledCorurses));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function destroy($userID){
        try {
            $user = HelperFunction::getUserById($userID);
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            if (intval( \request()->user()->id) !== intval($userID) && \request()->user()->type !== UserType::ADMIN){
                return $this->permissionDenide();
            }
            $user->delete();
            return $this->success(UserResource::make($user) , __('messages.user_controller.delete_user'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
