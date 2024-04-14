<?php

namespace App\Http;

use App\HttpResponse\HTTPResponse;
use App\Models\ActivationCode;
use App\Models\Category;
use App\Models\Chapter;
use App\Models\Choice;
use App\Models\Course;
use App\Models\CourseValue;
use App\Models\Lesion;
use App\Models\News;
use App\Models\Question;
use App\Models\Quiz;
use App\Models\User;

class HelperFunction
{
    use HTTPResponse;
    public static function getUserById ($userID , array $with = []){
        return User::with($with)->where('id' , $userID)->first();
    }

    public static function getCourseByID($courseID, array $with = []){
        return Course::with($with)->where('id' , $courseID)->first();
    }

    public static function getCategoryByID($categoryID ,  array $with = []){
        return Category::with($with)->where('id' , $categoryID)->first();
    }

    public static function getNewsByID($newsID){
        return News::where('id' , $newsID)->first();
    }

    public static function getChapterByID($chapterID){
        return Chapter::where('id' , $chapterID)->first();
    }

    public static function getLesionByID($lesionID){
        return Lesion::where('id' , $lesionID)->first();
    }
    public static function getQuestionByID($questionID){
        return Question::where('id' , $questionID)->first();
    }
    public static function getActivationCodeByCode($code){
        return ActivationCode::where('code' ,$code)->first();
    }

    public static function getChoiceByID($choiceID){
        return Choice::where('id' , $choiceID)->first();
    }

    public static function getCourseValueByID($valueID){
        return CourseValue::where("id" , $valueID)->first();
    }

    public static function getQuizByID($quizID){
        return Quiz::where('id' , $quizID)->first();
    }

    public static function ServerErrorResponse(){
        return (new HelperFunction)->error(__('messages.error.server_error') , 500);
    }

    public static function notFoundResponce(){
        return (new HelperFunction)->error(__('messages.error.not_found') , 404);
    }
}
