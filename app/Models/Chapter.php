<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Chapter extends Model
{
    use HasFactory;
    protected $guarded = ['id'];

    public function course(){
        return $this->belongsTo(Course::class);
    }

    public function lesions(){
        return $this->hasMany(Lesion::class);
    }

    public function visibleLesions(){
        return $this->lesions()->where('is_visible' , true);
    }

    public function quizzes(){
        return $this->belongsToMany(Quiz::class)->withPivot(['id' , 'is_visible' , 'is_free']);
    }

    public function visibleQuizzes(){
        return $this->belongsToMany(Quiz::class)->wherePivot('is_visible' , true)->withPivot(['id' , 'is_visible' , 'is_free']);
    }
}
