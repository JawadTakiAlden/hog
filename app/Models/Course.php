<?php

namespace App\Models;

use App\Types\CodeType;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\File;

class Course extends Model
{
    use HasFactory;
    protected $guarded = ['id'];

    public function accountInrolments(){
        return $this->hasMany(AccountInrolment::class);
    }

    public function courseCategorys(){
        return $this->hasMany(CourseCategory::class);
    }


    public function setImageAttribute ($image){
        //TODO remove in production without seeders
        if (!$image){
            return $this->attributes['image'] = fake()->imageUrl;
        }
        $newImageName = uniqid() . '_' . 'image' . '.' . $image->extension();
        $image->move(public_path('course_images') , $newImageName);
        return $this->attributes['image'] =  '/'.'course_images'.'/' . $newImageName;
    }

//    protected static function boot()
//    {
//        parent::boot();
//        static::deleting(function ($course) {
//            if ($course->image){
//                $imagePath = public_path($course->image);
//                if (File::exists($imagePath)) {
//                    File::delete($imagePath);
//                }
//            }
//
//        });
//        static::updated(function ($course) {
//            if ($course->image){
//                if ($course->isDirty('image')) {
//                    $oldImagePath = public_path($course->getOriginal('image'));
//                    if (File::exists($oldImagePath)) {
//                        File::delete($oldImagePath);
//                    }
//                }
//            }
//
//        });
//    }

    public function numberOfEnrolmentBySingleCode(){
        $countBySingle = AccountInrolment::where('course_id' , $this->id)
            ->whereHas('activationCode' , fn($query) =>
                $query->where('type' , CodeType::SINGLE)
            )->count();

        $countByShared = AccountInrolment::where('course_id' , $this->id)
            ->whereHas('activationCode' , fn($query) =>
            $query->where('type' , CodeType::SHARED)
            )->count();

        $countBySharedSelected = AccountInrolment::where('course_id' , $this->id)
            ->whereHas('activationCode' , fn($query) =>
            $query->where('type' , CodeType::SHARED_SELECTED)
            )->count();

        $countBySharedGift = AccountInrolment::where('course_id' , $this->id)
            ->whereHas('activationCode' , fn($query) =>
            $query->where('type' , CodeType::GIFt)
            )->count();

        $manualEnrolment = AccountInrolment::where('course_id' , $this->id)
            ->where('activation_code_id' , null)
            ->count();

        return [
            'count_by_single' => $countBySingle,
            'count_by_shared' => $countByShared,
            'count_by_shared_selected' => $countBySharedSelected,
            'manual_enrolment' => $manualEnrolment,
            'count_by_gift' => $countBySharedGift
        ];
    }


    public function categories(){
        return $this->belongsToMany(Category::class , 'course_categories');
    }

    public function scopeFilter($query , array $filters){
        $query->when($filters['search'] ?? false , fn($query , $search) =>
            $query->where('name' , 'LIKE' , '%'.$search.'%')
        );
    }

    public function teachers(){
        return $this->belongsToMany(User::class , 'course_teachers' , 'course_id', 'teacher_id');
    }

    public function teacherCourse(){
        return $this->hasMany(CourseTeacher::class);
    }

    public function chapters(){
        return $this->hasMany(Chapter::class);
    }

    public function courseValues(){
        return $this->hasMany(CourseValue::class);
    }

    public function students(){
        return $this->belongsToMany(User::class , 'account_inrolments')->withPivot(['created_at' , 'id']);
    }

    public function visibleChapters(){
        return $this->chapters()->where('is_visible' , true);
    }
}
