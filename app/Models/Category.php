<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Category extends Model
{
    use HasFactory;
    protected $guarded = ['id'];

    public function courseCategorys(){
        return $this->hasMany(CourseCategory::class);
    }

    public function courses()
    {
        return $this->belongsToMany(Course::class, 'course_categories');
    }
}
