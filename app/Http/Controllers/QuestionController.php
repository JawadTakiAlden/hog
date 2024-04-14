<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\StoreQuestionRequest;
use App\Http\Requests\UpdateQuestionRequest;
use App\Http\Resources\QuestionResource;
use App\HttpResponse\HTTPResponse;
use App\Models\Choice;
use App\Models\Question;
use App\Types\UpdateChoiceFlag;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class QuestionController extends Controller
{
    use HTTPResponse;
    public function getAll(){
        try {
            $questions = Question::all();
            return $this->success(QuestionResource::collection($questions));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function store(StoreQuestionRequest $request){
        try {
            $question = Question::create($request->only(['title' ,'image' , 'clarification_text','clarification_image']));
            return $this->success(QuestionResource::make($question) , __('messages.question_controller.create'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
    public function update(UpdateQuestionRequest $request , $questionID){
        try {
            $question = HelperFunction::getQuestionByID($questionID);
            if (!$questionID){
                return HelperFunction::notFoundResponce();
            }
            $question->update($request->only(['title' ,'image' , 'clarification_text','clarification_image']));
            return $this->success(QuestionResource::make($question) ,  __('messages.question_controller.update'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function show($questionID){
        try {
            $question = HelperFunction::getQuestionByID($questionID);
            if (!$question){
                return HelperFunction::notFoundResponce();
            }
            return $this->success(QuestionResource::make($question));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function destroy($questionID){
        try {
            $question = HelperFunction::getQuestionByID($questionID);
            if (!$question){
                return HelperFunction::notFoundResponce();
            }
            $question->delete();
            return $this->success(QuestionResource::make($question) , __('messages.question_controller.delete'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
