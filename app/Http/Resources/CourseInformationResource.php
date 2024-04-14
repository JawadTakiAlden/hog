<?php

namespace App\Http\Resources;

use App\Models\AccountInrolment;
use App\Models\CourseTeacher;
use App\Models\User;
use App\Types\UserType;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Auth;

class CourseInformationResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $is_paid = false;

        $user = $request->user();

        if ($user){
            $inrole = AccountInrolment::where('user_id' , $user->id)
                ->where('course_id' , $this->id)->first();
            if ($inrole){
                $is_paid = true;
            }
        }

        $teachOnIt = false;
        if ($user){
            if ($user->type === UserType::TEACHER){
                $teacherOfCourse = CourseTeacher::where('course_id' , $this->id)
                    ->where('teacher_id' , $user->id)->first();
                if ($teacherOfCourse){
                    $teachOnIt = true;
                }
            }
        }

        $totalTimeOfCourse = $this->visibleChapters
            ->map(fn($chapter) =>
                $chapter->visibleLesions->map(fn($lesion) =>
                    $lesion
                )->sum(fn($lesion) => $lesion->time)
            )->sum();

        $response = [
            'id' => intval($this->id),
            'name' => $this->name,
            'image' => $this->image ? asset($this->image) : null,
            'telegram_channel_link' => $this->telegram_channel_link,
            'is_open' => boolval($this->is_open),
            'is_visible' => boolval($this->is_visible),
            'is_paid' => boolval($is_paid),
            'total_time' => intval($totalTimeOfCourse),
            'teachers' => User::whereHas('teacherCourse' , fn($query) =>
            $query->where('course_id' , $this->id)
            )->get()->map(fn ($user) => $user->full_name),
            'chapters' => ChapterInforamtionResource::collection($this->visibleChapters),
            'values_of_course' => $this->courseValues
        ];
        if ($user){
            if ($user->type === UserType::TEACHER){
                $response = array_merge($response , ['is_teach_this_course' => boolval($teachOnIt)]);
            }
        }
        return $response;
    }
}
