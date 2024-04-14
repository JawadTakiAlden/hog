<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Quiz extends Model
{
    use HasFactory;

    protected $guarded = ['id'];


    public function forUserQuestions(){
        return $this->belongsToMany(Question::class , 'question_quizzes')->withPivot(['id' , 'is_visible'])->wherePivot('is_visible' , true);
    }
    public function forAdminQuestions(){
        return $this->belongsToMany(Question::class , 'question_quizzes')->withPivot(['id' , 'is_visible']);
    }
    public function invisibleQuestion(){
        return $this->belongsToMany(Question::class , 'question_quizzes')->withPivot(['id' , 'is_visible'])->wherePivot('is_visible' , false);
    }
}
