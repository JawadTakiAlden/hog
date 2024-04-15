<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\File;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;


    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $guarded = ['id'];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */

//    protected static function boot()
//    {
//        parent::boot();
//        static::deleting(function ($user) {
//            if ($user->image){
//                $imagePath = public_path($user->image);
//                if (File::exists($imagePath)) {
//                    File::delete($imagePath);
//                }
//            }
//        });
//        static::updated(function ($user) {
//            if ($user->image){
//                if ($user->isDirty('image')) {
//                    $oldImagePath = public_path($user->getOriginal('image'));
//                    if (File::exists($oldImagePath)) {
//                        File::delete($oldImagePath);
//                    }
//                }
//            }
//        });
//    }

    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
    ];


    public function accountInrolments(){
        return $this->hasMany(AccountInrolment::class);
    }

    public function setImageAttribute ($image){
        $newImageName = uniqid() . '_' . 'image' . '.' . $image->extension();
        $image->move(public_path('users_images') , $newImageName);
        return $this->attributes['image'] =  '/'.'users_images'.'/' . $newImageName;
    }

    public function teacherCourse(){
        return $this->hasMany(CourseTeacher::class , 'teacher_id');
    }
    public function inroledCorurses(){
        return $this->belongsToMany(Course::class , 'account_inrolments')->withPivot(['created_at']);
    }
}
