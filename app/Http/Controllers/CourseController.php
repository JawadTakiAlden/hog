<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\SignInCourseRequest;
use App\Http\Resources\AllInrolledResource;
use App\Http\Resources\CourseInformationResource;
use App\Http\Resources\CourseResource;
use App\Http\Resources\EnrollmentWithTypeOfCodeResource;
use App\Http\Resources\InrolmentsResource;
use App\Http\Resources\ShowCourseInformationForAdmin;
use App\HttpResponse\HTTPResponse;
use App\Models\AccountInrolment;
use App\Models\ActivationCode;
use App\Models\Course;
use App\Http\Requests\StoreCourseRequest;
use App\Http\Requests\UpdateCourseRequest;
use App\Models\CourseCanActivated;
use App\Models\CourseCategory;
use App\Models\CourseTeacher;
use App\Models\CourseValue;
use App\Types\CodeType;
use App\Types\UserType;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class CourseController extends Controller
{
    use HTTPResponse;

    public function getAllCourses(){
        try {
            $courses = Course::all();
            return $this->success(CourseResource::collection($courses));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getAllIneolments(){
        try {
            $inrolments = AccountInrolment::with(['course', 'user', 'activationCode'])->orderByDesc('created_at')->get();
            return $this->success(AllInrolledResource::collection($inrolments));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }


    public function getEnrollmentWithTypeOfCodes(){
        try {
        $courses = Course::all();
        return $this->success(EnrollmentWithTypeOfCodeResource::collection($courses));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }

    }

    public function visibleCourses(){
        try {
            $courses = Course::where('is_visible' , true)->get();
            return $this->success(CourseResource::collection($courses));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
    public function search() {
        try {
            $courses = Course::where('is_visible' , true)->filter(request(['search']))->get();
            return CourseResource::collection($courses);
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
    public function getVisibleCourses($categoryID){
        try {
            $category = HelperFunction::getCategoryByID($categoryID , ['courses']);
            if (!$category){
                return HelperFunction::notFoundResponce();
            }
            return $this->success(CourseResource::collection($category->courses->where('is_visible' , '=' , true)));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function destroy($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $course->delete();
            return $this->success(CourseResource::make($course) , __("message.course_controller.delete"));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function cancelInfolement($inrolmentID){
        try {
            $inrolment = AccountInrolment::where('id' ,$inrolmentID )->first();
            if (!$inrolment){
                return HelperFunction::notFoundResponce();
            }
            $inrolment->delete();
            return $this->success(null , __("message.course_controller.cancel_enrolment"));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function makeCourseVisible($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $course->update([
                'is_visible' => true
            ]);
            return $this->success(CourseResource::make($course));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function makeCourseInvisible($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $course->update([
                'is_visible' => false
            ]);
            return $this->success(CourseResource::make($course));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function switchVisibility($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $course->update([
                'is_visible' => !$course->is_visible
            ]);
            return $this->success(CourseResource::make($course) , __('messages.course_controller.visibility_switch'));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }


    public function switchOpenStatus($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $course->update([
                'is_open' => !$course->is_open
            ]);
            return $this->success(CourseResource::make($course) , __('messages.course_controller.free_switch' , ['status' => $course->is_open ? 'Free' : "Not Free"]));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function manualInrolStudentInCourse($userID , $courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            $user = HelperFunction::getUserById($userID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            if (!boolval($course->is_visible)){
                return $this->error(__('messages.course_controller.error.invisible_course') , 403);
            }
            if (!$user){
                return HelperFunction::notFoundResponce();
            }
            $preInrolled = AccountInrolment::where('user_id' , $userID)->where('course_id' , $courseID)->first();
            if ($preInrolled){
                return $this->error( __('messages.course_controller.error.already_enrolled' , [
                    'username' => $user->full_name,
                    "course_name" => $course->name
                ]) , 422);
            }
            AccountInrolment::create([
                'user_id' => $user->id,
                'course_id' => $course->id
            ]);
            return $this->success(null , __("messages.course_controller.manual_enrolled_successfully" , [
                'username' => $user->full_name,
                'course_name' => $course->name
            ]));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function store(StoreCourseRequest $request){
        try {
            DB::beginTransaction();
            $course = Course::create($request->only(['name', 'image', 'is_visible', 'is_open' , 'telegram_channel_link']));
            if ($request->categories) {
                foreach ($request->categories as $category) {
                    CourseCategory::create([
                        'course_id' => $course->id,
                        'category_id' => $category
                    ]);
                }
            } else {
                return $this->error(__('messages.course_controller.error.one_category_at_least'), 422);
            }
            if ($request->teachers) {
                foreach ($request->teachers as $teacher) {
                    CourseTeacher::create([
                        'course_id' => $course->id,
                        'teacher_id' => $teacher
                    ]);
                }
            } else {
                return $this->error(__('messages.course_controller.error.one_teacher_at_least'), 422);
            }
            if ($request->values) {
                foreach ($request->values as $value) {
                    CourseValue::create([
                        'course_id' => $course->id,
                        'value' => $value
                    ]);
                }
            }
            DB::commit();
            $notification = new NotificationController();
            $notification->addNewCourseNotification($course);
            return $this->success(CourseResource::make($course) , __('messages.course_controller.create' , ['course_name' => $course->name]));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function showCourseWithInfo($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            if (Auth::user()->type === UserType::ADMIN){
                return $this->success(ShowCourseInformationForAdmin::make($course));
            }
            return $this->success(CourseInformationResource::make($course));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function update(UpdateCourseRequest $request , $courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            DB::beginTransaction();
            $course->update($request->only(['name' , 'image' , 'is_open' , 'is_visible' , 'telegram_channel_link']));
            $course->categories()->sync($request->categories);
            $course->teachers()->sync($request->teachers);
            DB::commit();
            return $this->success(CourseResource::make($course) , __('messages.course_controller.update' , ['course_name' => $course->name]));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function inrollInCourse (SignInCourseRequest $request , $courseID) {
        $request->validated($request->only('code'));
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            if (!boolval($course->is_visible)){
                return $this->error(__('messages.course_controller.error.invisible_course') , 403);
            }
            $existingInrole = AccountInrolment::where('user_id' , $request->user()->id)
                ->where('course_id' , $courseID)->first();
            if ($existingInrole){
                return $this->error(trans('messages.course_controller.error.user_already_enrolled') , 403);
            }
            $code = HelperFunction::getActivationCodeByCode(strval($request->activation_code));
            if (!$code){
                return $this->error(trans('messages.error.activation_code_not_found'), 403);
            }
            if (intval($code->times_of_usage) === 0){
                return $this->error(trans('messages.error.activation_code_expired') , 403);
            }
            if ($code->type === CodeType::SHARED_SELECTED){
                $courseAlreadyActivatedByCode = CourseCanActivated::where('activation_code_id' , $code->id)
                    ->where('course_id' , $course->id)->first();
                if ($courseAlreadyActivatedByCode){
                    return $this->error(trans('messages.error.shared_activation_code_already_used_for_this_course')  , 403);
                }
                DB::beginTransaction();
                $code->update([
                   'times_of_usage' =>  intval($code->times_of_usage) - 1
                ]);

                AccountInrolment::create([
                   'user_id' => Auth::user()->id,
                    'activation_code_id' => $code->id,
                    'course_id' => $course->id
                ]);

                CourseCanActivated::create([
                    'course_id' => $course->id,
                    'activation_code_id' => $code->id,
                    'is_used' => true
                ]);
                DB::commit();
                return $this->success(null , trans('messages.course_controller.enroll_successfully' , ['course_name' => $course->name]));
            }
            $coursesCanBeActivatedByThisCode =
                collect($code->courseCanActivated)
                    ->filter(fn($code) => intval($code->course_id) === intval($course->id));

            if (count($coursesCanBeActivatedByThisCode) === 0){
                return $this->error(trans('messages.course_controller.error.wrong_match_course_with_code'), 403);
            }
            $courseToActive = $coursesCanBeActivatedByThisCode->first();
            if ($courseToActive->is_used){
                return $this->error(trans('messages.course_controller.error.user_already_enrolled'), 422);
            }
            DB::beginTransaction();
            AccountInrolment::create([
                'course_id' => $course->id,
                'user_id' => Auth::user()->id,
                'activation_code_id' => $code->id
            ]);
            $code->update([
                'times_of_usage' => intval($code->times_of_usage) - 1
            ]);
            CourseCanActivated::where('id' , $courseToActive->id)->update(['is_used' => true]);
            DB::commit();
            return $this->success(null , __('messages.course_controller.enroll_successfully' ,  ['course_name' => $course->name]));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }
}
