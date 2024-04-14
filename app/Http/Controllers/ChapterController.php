<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Resources\ChapterResource;
use App\HttpResponse\HTTPResponse;
use App\Models\Chapter;
use App\Http\Requests\StoreChapterRequest;
use App\Http\Requests\UpdateChapterRequest;

class ChapterController extends Controller
{
    use HTTPResponse;
    public function getAll($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $chapters = Chapter::where('course_id' , $courseID)->get();
            return $this->success(ChapterResource::collection($chapters));
        }catch (\Throwable $th){
            return $this->catchError($th);
        }
    }

    public function getVisible($courseID){
        try {
            $course = HelperFunction::getCourseByID($courseID);
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $chapters = Chapter::where('course_id' , $courseID)->where('is_visible' , true)->get();
            return $this->success(ChapterResource::collection($chapters));
        }catch (\Throwable $th){
            return $this->catchError($th);
        }
    }
    public function switchVisibility($chapterID) {
        try {
            $chapter = HelperFunction::getChapterByID($chapterID);
            if (!$chapter){
                return HelperFunction::notFoundResponce();
            }
            $chapter->update([
               'is_visible' => !$chapter->is_visible
            ]);
            return $this->success(ChapterResource::make($chapter) , __("messages.chapter_controller.visibility_switch"));
        }catch(\Throwable $th){
            return $this->catchError($th);
        }
    }

    public function destroy($chapterID){
        try {
            $chapter = HelperFunction::getChapterByID($chapterID);
            if (!$chapter){
                return HelperFunction::notFoundResponce();
            }
            $chapter->delete();
            return $this->success(ChapterResource::make($chapter) ,  __("messages.chapter_controller.delete"));
        }catch(\Throwable $th){
            return $this->catchError($th);
        }
    }

    public function store(StoreChapterRequest $request){
        try {
            $course = HelperFunction::getCourseByID(intval($request->course_id));
            if (!$course){
                return HelperFunction::notFoundResponce();
            }
            $chapter = Chapter::create($request->only('name' , 'course_id' , 'is_visible'));
            return $this->success(ChapterResource::make($chapter) ,  __("messages.chapter_controller.create"));
        }catch (\Throwable $th){
            return $this->catchError($th);
        }
    }

    public function update(UpdateChapterRequest $request , $chapterID){
        try {
            $chapter = HelperFunction::getChapterByID($chapterID);
            if (!$chapter){
                return HelperFunction::notFoundResponce();
            }
            $chapter->update($request->only(['name' , 'is_visible']));
            return $this->success(ChapterResource::make($chapter) ,  __("messages.chapter_controller.update"));
        }catch (\Throwable $th){
            return $this->catchError($th);
        }
    }

}
