<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\StoreCourseValueRequest;
use App\Http\Requests\UpdateCourseValueRequest;
use App\Http\Resources\CourseResource;
use App\HttpResponse\HTTPResponse;
use App\Models\CourseValue;
use Illuminate\Http\Request;

class CourseValueController extends Controller
{
    use HTTPResponse;
    public function store(StoreCourseValueRequest $request , $courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $newCourseValue = CourseValue::create( array_merge($request->only(['value']), ['course_id' => $courseID]));
            return $this->success(CourseResource::make($newCourseValue->course) , __('messages.course_value_controller.create' , ['value_name' => $newCourseValue->value]));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function update(UpdateCourseValueRequest $request , $valueID){
        try {
            $value = HelperFunction::getCourseValueByID($valueID);
            if (!$value){
                return HelperFunction::notFoundResponce();
            }
            $value->update($request->only(['value']));
            return $this->success(CourseResource::make($value->course) , __('messages.course_value_controller.update' , ['value_name' => $value->value]));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function destroy($valueID){
        try {
            $value = HelperFunction::getCourseValueByID($valueID);
            if (!$value){
                return HelperFunction::notFoundResponce();
            }
            $value->delete();
            return $this->success(CourseResource::make($value->course) , __('messages.course_value_controller.delete' , ['value_name' => $value->value]));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
