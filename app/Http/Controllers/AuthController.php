<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\LoginAdminRequest;
use App\Http\Requests\LoginUserRequest;
use App\Http\Requests\SignUpRequest;
use App\Http\Resources\UserResource;
use App\HttpResponse\HTTPResponse;
use App\Models\User;
use App\Types\UserType;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class AuthController extends Controller
{
    use HTTPResponse;
    public function signup (SignUpRequest $request) {
        try {
            DB::beginTransaction();
            $user = $request->only(
                [
                    'full_name' ,
                    'image' ,
                    'device_notification_id' ,
                    'phone' ,
                    'password' ,
                    'device_id'
                ]
            );
//            $user = User::create();
            DB::commit();
            return $this->success($user , 'تحت الصيانة الرجاء الانتظاء والمحاولة بعد ساعة من الان');
//            return $this->success([
//                "token" =>  $user->createToken("API TOKEN")->plainTextToken,
//                "user" => UserResource::make($user)
//            ] , __('messages.auth_controller.register'));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function loginAdmin(LoginAdminRequest $request){
        try {
            DB::beginTransaction();
            $user = User::where('phone', $request->phone)->first();
            if (!$user){
                return $this->error(
                    __('messages.not_found')
                    , 401);
            }
            if (strval($user->type) !== UserType::ADMIN){
                return $this->error(
                    __('messages.error.admin_permission')
                    , 403);
            }
            if (!Auth::attempt($request->only(['phone', 'password']))) {
                return $this->error(__('messages.auth_controller.error.credentials_error')
                    , 401);
            }
            $token = $user->createToken('API TOKEN')->plainTextToken;
            DB::commit();
            return $this->success([
                "token" => $token,
                "user" => UserResource::make($user),
            ] , __('messages.auth_controller.login' , ['user_name' => $user->full_name]));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function login(LoginUserRequest $request){
        try {
            DB::beginTransaction();
            $user = User::where('phone', $request->phone)->first();
            if (!$user){
                return $this->error(
                    __('messages.not_found')
                , 404);
            }
            if ($user->is_blocked){
                return $this->error(__('messages.error.blocked_account'), 403);
            }

            if (boolval($user->device_id)){
                if ($user->device_id !== $request->device_id){
                    $user->update([
                        'is_blocked' => true,
                    ]);
                    $user->tokens()->delete();
                    DB::commit();
                    return $this->error(trans('messages.auth_controller.error.block_account_while_login'), 403);
                }
            }
            if (!Auth::attempt($request->only(['phone', 'password']))) {
                return $this->error(__('messages.auth_controller.error.credentials_error')
                    , 401);
            }
            if (!$user->device_id){
                $user->update([
                    'device_id' => $request->device_id ?? null
                ]);
            }
            $token = $user->createToken('API TOKEN')->plainTextToken;
            $user->update([
               'device_notification_id' => $request->device_notification_id
            ]);
            DB::commit();
            return $this->success([
                "token" => $token,
                "user" => UserResource::make($user),
            ] , __('messages.auth_controller.login' , [ 'user_name' => $user->full_name ]));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function logout(){
        try {
            DB::beginTransaction();
            $user = Auth::user();
            $user->currentAccessToken()->delete();
            DB::commit();
            return $this->success($user , __('messages.auth_controller.logout' , ['name' => $user->full_name]));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function refreshToken(){
        //TODO
//        refresh token logic
    }
}
